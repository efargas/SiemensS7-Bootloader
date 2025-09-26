using System;
using System.Diagnostics;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using S7.Core.Abstractions.Validation;

namespace S7.Core.Abstractions.Commands
{
    /// <summary>
    /// Generic base class for command handlers providing common functionality including validation, logging, and exception handling.
    /// </summary>
    /// <typeparam name="TOptions">The type of options for this command handler</typeparam>
    public abstract class CommandHandler<TOptions> where TOptions : CommandHandlerOptions
    {
        /// <summary>
        /// Gets the logger instance for this command handler.
        /// </summary>
        protected ILogger Logger { get; }

        /// <summary>
        /// Gets the validator for command options.
        /// </summary>
        protected IValidator<TOptions>? Validator { get; }

        /// <summary>
        /// Initializes a new instance of the CommandHandler class.
        /// </summary>
        /// <param name="logger">The logger instance</param>
        /// <param name="validator">The optional validator for command options</param>
        protected CommandHandler(ILogger logger, IValidator<TOptions>? validator = null)
        {
            Logger = logger ?? throw new ArgumentNullException(nameof(logger));
            Validator = validator;
        }

        /// <summary>
        /// Executes the command with the specified options.
        /// </summary>
        /// <param name="options">The command options</param>
        /// <param name="cancellationToken">Cancellation token for the operation</param>
        /// <returns>A task representing the command execution result</returns>
        public async Task<CommandResult<TResult>> ExecuteAsync<TResult>(
            TOptions options, 
            CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(options);

            var correlationId = options.CorrelationId;
            var stopwatch = Stopwatch.StartNew();

            if (options.EnableDetailedLogging)
            {
                Logger.LogInformation("Starting command execution. CorrelationId: {CorrelationId}, CommandType: {CommandType}, Priority: {Priority}",
                    correlationId, GetType().Name, options.Priority);
            }

            try
            {
                // Create combined cancellation token with timeout
                using var timeoutCts = new CancellationTokenSource(TimeSpan.FromMilliseconds(options.TimeoutMs));
                using var combinedCts = CancellationTokenSource.CreateLinkedTokenSource(
                    cancellationToken, 
                    timeoutCts.Token, 
                    options.CancellationToken);

                // Validate options
                var validationResult = await ValidateOptionsAsync(options, combinedCts.Token).ConfigureAwait(false);
                if (!validationResult.IsValid)
                {
                    Logger.LogWarning("Command validation failed. CorrelationId: {CorrelationId}, Errors: {Errors}",
                        correlationId, string.Join(", ", validationResult.Errors));
                    return CommandResult<TResult>.ValidationFailure(validationResult.Errors, correlationId);
                }

                // Execute the command with retry policy if configured
                TResult result;
                if (options.RetryPolicy != null)
                {
                    result = await ExecuteWithRetryAsync<TResult>(options, combinedCts.Token).ConfigureAwait(false);
                }
                else
                {
                    result = await ExecuteInternalAsync<TResult>(options, combinedCts.Token).ConfigureAwait(false);
                }

                stopwatch.Stop();

                if (options.EnableDetailedLogging)
                {
                    Logger.LogInformation("Command execution completed successfully in {Duration}ms. CorrelationId: {CorrelationId}",
                        stopwatch.ElapsedMilliseconds, correlationId);
                }

                return CommandResult<TResult>.Success(result, correlationId);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                stopwatch.Stop();
                Logger.LogInformation("Command execution was cancelled by caller after {Duration}ms. CorrelationId: {CorrelationId}",
                    stopwatch.ElapsedMilliseconds, correlationId);
                return CommandResult<TResult>.Failure("Operation was cancelled", correlationId);
            }
            catch (OperationCanceledException)
            {
                stopwatch.Stop();
                Logger.LogWarning("Command execution timed out after {Duration}ms. CorrelationId: {CorrelationId}",
                    stopwatch.ElapsedMilliseconds, correlationId);
                return CommandResult<TResult>.Failure($"Operation timed out after {options.TimeoutMs}ms", correlationId);
            }
            catch (Exception ex)
            {
                stopwatch.Stop();
                Logger.LogError(ex, "Command execution failed after {Duration}ms. CorrelationId: {CorrelationId}",
                    stopwatch.ElapsedMilliseconds, correlationId);
                return CommandResult<TResult>.FromException(ex, correlationId);
            }
        }

        /// <summary>
        /// Validates the command options asynchronously.
        /// </summary>
        /// <param name="options">The command options to validate</param>
        /// <param name="cancellationToken">Cancellation token for the operation</param>
        /// <returns>A task representing the validation result</returns>
        protected virtual async Task<ValidationResult> ValidateOptionsAsync(
            TOptions options, 
            CancellationToken cancellationToken = default)
        {
            // Use built-in validation from options
            var builtInValidation = options.Validate();
            if (builtInValidation.Any())
            {
                var errors = builtInValidation.Select(vr => vr.ErrorMessage ?? "Unknown validation error").ToList();
                return ValidationResult.Failure(errors);
            }

            // Use injected validator if available
            if (Validator != null)
            {
                var validatorResult = Validator.Validate(options);
                if (!validatorResult.IsValid)
                {
                    return validatorResult;
                }
            }

            // Allow derived classes to add custom validation
            return await ValidateOptionsInternalAsync(options, cancellationToken).ConfigureAwait(false);
        }

        /// <summary>
        /// Provides custom validation logic for derived classes.
        /// </summary>
        /// <param name="options">The command options to validate</param>
        /// <param name="cancellationToken">Cancellation token for the operation</param>
        /// <returns>A task representing the validation result</returns>
        protected virtual Task<ValidationResult> ValidateOptionsInternalAsync(
            TOptions options, 
            CancellationToken cancellationToken = default)
        {
            return Task.FromResult(ValidationResult.Success());
        }

        /// <summary>
        /// Executes the command with retry policy.
        /// </summary>
        /// <typeparam name="TResult">The type of result to return</typeparam>
        /// <param name="options">The command options</param>
        /// <param name="cancellationToken">Cancellation token for the operation</param>
        /// <returns>A task representing the command execution result</returns>
        private async Task<TResult> ExecuteWithRetryAsync<TResult>(
            TOptions options, 
            CancellationToken cancellationToken)
        {
            var retryPolicy = options.RetryPolicy!;
            var attempt = 0;
            Exception? lastException = null;

            while (attempt <= retryPolicy.MaxRetries)
            {
                try
                {
                    if (attempt > 0)
                    {
                        var delay = retryPolicy.UseExponentialBackoff 
                            ? retryPolicy.RetryDelayMs * (int)Math.Pow(2, attempt - 1)
                            : retryPolicy.RetryDelayMs;

                        Logger.LogInformation("Retrying command execution (attempt {Attempt}/{MaxRetries}) after {Delay}ms delay. CorrelationId: {CorrelationId}",
                            attempt, retryPolicy.MaxRetries, delay, options.CorrelationId);

                        await Task.Delay(delay, cancellationToken).ConfigureAwait(false);
                    }

                    return await ExecuteInternalAsync<TResult>(options, cancellationToken).ConfigureAwait(false);
                }
                catch (Exception ex) when (ShouldRetry(ex, retryPolicy))
                {
                    lastException = ex;
                    attempt++;

                    if (attempt <= retryPolicy.MaxRetries)
                    {
                        Logger.LogWarning(ex, "Command execution failed (attempt {Attempt}/{MaxRetries}), will retry. CorrelationId: {CorrelationId}",
                            attempt, retryPolicy.MaxRetries, options.CorrelationId);
                    }
                }
            }

            // All retries exhausted
            Logger.LogError(lastException, "Command execution failed after {MaxRetries} retries. CorrelationId: {CorrelationId}",
                retryPolicy.MaxRetries, options.CorrelationId);
            throw lastException ?? new InvalidOperationException("Command execution failed with unknown error");
        }

        /// <summary>
        /// Determines whether an exception should trigger a retry.
        /// </summary>
        /// <param name="exception">The exception that occurred</param>
        /// <param name="retryPolicy">The retry policy configuration</param>
        /// <returns>True if the operation should be retried, false otherwise</returns>
        private static bool ShouldRetry(Exception exception, RetryPolicy retryPolicy)
        {
            if (retryPolicy.RetryableExceptions.Length == 0)
            {
                // If no specific exceptions are configured, retry on all non-critical exceptions
                return exception is not (OperationCanceledException or ArgumentException or ArgumentNullException);
            }

            // Check if the exception type is in the retryable exceptions list
            var exceptionType = exception.GetType();
            return retryPolicy.RetryableExceptions.Any(retryableType => 
                retryableType.IsAssignableFrom(exceptionType));
        }

        /// <summary>
        /// Executes the command implementation. Must be implemented by derived classes.
        /// </summary>
        /// <typeparam name="TResult">The type of result to return</typeparam>
        /// <param name="options">The command options</param>
        /// <param name="cancellationToken">Cancellation token for the operation</param>
        /// <returns>A task representing the command execution result</returns>
        protected abstract Task<TResult> ExecuteInternalAsync<TResult>(
            TOptions options, 
            CancellationToken cancellationToken = default);
    }
}