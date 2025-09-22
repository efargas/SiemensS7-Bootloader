using Microsoft.Extensions.Logging;
using System;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace S7.Core.Commands
{
    /// <summary>
    /// Abstract base class for command handlers that provides common functionality.
    /// </summary>
    /// <typeparam name="TOptions">The type of options required for the command</typeparam>
    public abstract class CommandHandler<TOptions> : ICommandHandler<TOptions>
        where TOptions : CommandHandlerOptions
    {
        /// <summary>
        /// Gets the logger instance for this command handler.
        /// </summary>
        protected ILogger Logger { get; }

        /// <summary>
        /// Initializes a new instance of the CommandHandler class.
        /// </summary>
        /// <param name="logger">The logger instance</param>
        protected CommandHandler(ILogger logger)
        {
            Logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        /// <summary>
        /// Handles the command asynchronously with the provided options.
        /// </summary>
        /// <param name="options">The command options</param>
        /// <param name="cancellationToken">Cancellation token for the operation</param>
        /// <returns>A command result indicating success or failure</returns>
        public async Task<CommandResult> HandleAsync(TOptions options, CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(options);

            var commandType = typeof(TOptions).Name;
            Logger.LogInformation("Starting command execution: {CommandType} [CorrelationId: {CorrelationId}]", 
                commandType, options.CorrelationId);

            try
            {
                // Validate the options
                var validationResult = ValidateOptions(options);
                if (!validationResult.IsValid)
                {
                    Logger.LogWarning("Command validation failed: {CommandType} [CorrelationId: {CorrelationId}] - {ErrorMessage}", 
                        commandType, options.CorrelationId, validationResult.ErrorMessage);
                    return CommandResult.ValidationFailure(validationResult.Errors);
                }

                Logger.LogDebug("Command validation successful: {CommandType} [CorrelationId: {CorrelationId}]", 
                    commandType, options.CorrelationId);

                // Execute the command
                var result = await ExecuteAsync(options, cancellationToken).ConfigureAwait(false);

                if (result.IsSuccess)
                {
                    Logger.LogInformation("Command completed successfully: {CommandType} [CorrelationId: {CorrelationId}]", 
                        commandType, options.CorrelationId);
                }
                else
                {
                    Logger.LogWarning("Command completed with failure: {CommandType} [CorrelationId: {CorrelationId}] - {ErrorMessage}", 
                        commandType, options.CorrelationId, result.ErrorMessage);
                }

                return result;
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                Logger.LogInformation("Command was cancelled: {CommandType} [CorrelationId: {CorrelationId}]", 
                    commandType, options.CorrelationId);
                return CommandResult.Failure("Operation was cancelled");
            }
            catch (Exception ex)
            {
                Logger.LogError(ex, "Command execution failed with exception: {CommandType} [CorrelationId: {CorrelationId}]", 
                    commandType, options.CorrelationId);
                return CommandResult.FromException(ex);
            }
        }

        /// <summary>
        /// Executes the specific command logic.
        /// </summary>
        /// <param name="options">The command options</param>
        /// <param name="cancellationToken">Cancellation token for the operation</param>
        /// <returns>A command result indicating success or failure</returns>
        protected abstract Task<CommandResult> ExecuteAsync(TOptions options, CancellationToken cancellationToken);

        /// <summary>
        /// Validates the command options. Override this method to provide custom validation logic.
        /// </summary>
        /// <param name="options">The command options to validate</param>
        /// <returns>A validation result indicating success or failure</returns>
        protected virtual ValidationResult ValidateOptions(TOptions options)
        {
            // Use data annotations for basic validation
            var validationContext = new ValidationContext(options);
            var validationResults = new System.Collections.Generic.List<ValidationResult>();
            
            if (Validator.TryValidateObject(options, validationContext, validationResults, true))
            {
                return ValidationResult.Success();
            }

            var errors = validationResults.Select(vr => vr.ErrorMessage ?? "Unknown validation error").ToList();
            return ValidationResult.Failure(errors);
        }

        /// <summary>
        /// Logs a progress update for the command execution.
        /// </summary>
        /// <param name="message">The progress message</param>
        /// <param name="correlationId">The correlation ID for tracking</param>
        protected void LogProgress(string message, string correlationId)
        {
            Logger.LogInformation("Progress: {Message} [CorrelationId: {CorrelationId}]", message, correlationId);
        }

        /// <summary>
        /// Logs a debug message for the command execution.
        /// </summary>
        /// <param name="message">The debug message</param>
        /// <param name="correlationId">The correlation ID for tracking</param>
        protected void LogDebug(string message, string correlationId)
        {
            Logger.LogDebug("Debug: {Message} [CorrelationId: {CorrelationId}]", message, correlationId);
        }
    }
}