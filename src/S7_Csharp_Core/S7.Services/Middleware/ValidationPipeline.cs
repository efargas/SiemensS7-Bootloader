using Microsoft.Extensions.Logging;
using S7.Core.Abstractions.Commands;
using S7.Core.Abstractions.Middleware;
using S7.Utils;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Threading;
using System.Threading.Tasks;

namespace S7.Services.Middleware
{
    /// <summary>
    /// Implementation of validation pipeline that orchestrates multiple validation middleware components.
    /// </summary>
    public class ValidationPipeline(ILogger<ValidationPipeline> logger) : IValidationPipeline
    {
        private readonly ILogger<ValidationPipeline> _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        private readonly ConcurrentDictionary<Type, List<object>> _middlewareRegistry = new();

        /// <summary>
        /// Executes the validation pipeline for the specified command options.
        /// </summary>
        /// <typeparam name="TOptions">The type of command options to validate.</typeparam>
        /// <param name="options">The command options to validate.</param>
        /// <param name="cancellationToken">Cancellation token for the operation.</param>
        /// <returns>A result indicating whether all validations passed or failed with aggregated error details.</returns>
        public async Task<Result<ValidationPipelineResult>> ExecuteAsync<TOptions>(TOptions options, CancellationToken cancellationToken = default) 
            where TOptions : CommandHandlerOptions
        {
            ArgumentNullException.ThrowIfNull(options);

            var stopwatch = Stopwatch.StartNew();
            var result = new ValidationPipelineResult();
            var optionsType = typeof(TOptions);

            try
            {
                _logger.LogInformation("Starting validation pipeline for {OptionsType} with CorrelationId {CorrelationId}", 
                    optionsType.Name, options.CorrelationId);

                // Get registered middleware for this options type
                if (!_middlewareRegistry.TryGetValue(optionsType, out var middlewareList) || !middlewareList.Any())
                {
                    _logger.LogDebug("No validation middleware registered for {OptionsType}", optionsType.Name);
                    result.IsValid = true;
                    result.ExecutionTime = stopwatch.Elapsed;
                    return Result<ValidationPipelineResult>.Success(result);
                }

                // Sort middleware by order
                var sortedMiddleware = middlewareList
                    .Cast<IValidationMiddleware<TOptions>>()
                    .OrderBy(m => m.Order)
                    .ToList();

                _logger.LogDebug("Executing {MiddlewareCount} validation middleware components for {OptionsType}", 
                    sortedMiddleware.Count, optionsType.Name);

                // Execute middleware in order
                foreach (var middleware in sortedMiddleware)
                {
                    cancellationToken.ThrowIfCancellationRequested();

                    var middlewareName = middleware.GetType().Name;
                    _logger.LogDebug("Executing validation middleware {MiddlewareName} (Order: {Order})", 
                        middlewareName, middleware.Order);

                    try
                    {
                        var middlewareResult = await middleware.ValidateAsync(options, cancellationToken).ConfigureAwait(false);
                        result.MiddlewareExecuted++;

                        if (!middlewareResult.IsSuccess)
                        {
                            var error = new ValidationError
                            {
                                PropertyName = "General",
                                ErrorMessage = middlewareResult.Error.Message,
                                MiddlewareName = middlewareName,
                                Severity = ValidationSeverity.Error
                            };

                            result.Errors.Add(error);
                            result.IsValid = false;

                            _logger.LogWarning("Validation middleware {MiddlewareName} failed: {ErrorMessage}", 
                                middlewareName, middlewareResult.Error.Message);

                            // Stop pipeline if middleware requires it
                            if (middleware.StopOnFailure)
                            {
                                _logger.LogWarning("Validation pipeline stopped due to {MiddlewareName} failure (StopOnFailure=true)", 
                                    middlewareName);
                                break;
                            }
                        }
                        else
                        {
                            _logger.LogDebug("Validation middleware {MiddlewareName} passed", middlewareName);
                        }
                    }
                    catch (OperationCanceledException)
                    {
                        _logger.LogInformation("Validation pipeline cancelled during {MiddlewareName} execution", middlewareName);
                        throw;
                    }
                    catch (Exception ex)
                    {
                        _logger.LogError(ex, "Unexpected error in validation middleware {MiddlewareName}", middlewareName);

                        var error = new ValidationError
                        {
                            PropertyName = "General",
                            ErrorMessage = $"Validation middleware error: {ex.Message}",
                            MiddlewareName = middlewareName,
                            Severity = ValidationSeverity.Critical
                        };

                        result.Errors.Add(error);
                        result.IsValid = false;

                        // Always stop on unexpected exceptions
                        break;
                    }
                }

                result.ExecutionTime = stopwatch.Elapsed;

                _logger.LogInformation("Validation pipeline completed for {OptionsType}. Valid: {IsValid}, Errors: {ErrorCount}, Executed: {MiddlewareExecuted}, Duration: {Duration}ms",
                    optionsType.Name, result.IsValid, result.Errors.Count, result.MiddlewareExecuted, result.ExecutionTime.TotalMilliseconds);

                return Result<ValidationPipelineResult>.Success(result);
            }
            catch (OperationCanceledException)
            {
                _logger.LogInformation("Validation pipeline cancelled for {OptionsType}", optionsType.Name);
                throw;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Unexpected error in validation pipeline for {OptionsType}", optionsType.Name);
                return Result<ValidationPipelineResult>.Failure($"Validation pipeline error: {ex.Message}");
            }
            finally
            {
                stopwatch.Stop();
            }
        }

        /// <summary>
        /// Registers a validation middleware for a specific command options type.
        /// </summary>
        /// <typeparam name="TOptions">The type of command options.</typeparam>
        /// <param name="middleware">The validation middleware to register.</param>
        public void RegisterMiddleware<TOptions>(IValidationMiddleware<TOptions> middleware) 
            where TOptions : CommandHandlerOptions
        {
            ArgumentNullException.ThrowIfNull(middleware);

            var optionsType = typeof(TOptions);
            var middlewareName = middleware.GetType().Name;

            _middlewareRegistry.AddOrUpdate(
                optionsType,
                new List<object> { middleware },
                (key, existingList) =>
                {
                    existingList.Add(middleware);
                    return existingList;
                });

            _logger.LogInformation("Registered validation middleware {MiddlewareName} for {OptionsType} (Order: {Order}, StopOnFailure: {StopOnFailure})",
                middlewareName, optionsType.Name, middleware.Order, middleware.StopOnFailure);
        }

        /// <summary>
        /// Gets the count of registered middleware for a specific options type.
        /// </summary>
        /// <typeparam name="TOptions">The type of command options.</typeparam>
        /// <returns>The number of registered middleware components.</returns>
        public int GetMiddlewareCount<TOptions>() where TOptions : CommandHandlerOptions
        {
            var optionsType = typeof(TOptions);
            return _middlewareRegistry.TryGetValue(optionsType, out var middlewareList) ? middlewareList.Count : 0;
        }

        /// <summary>
        /// Clears all registered middleware for a specific options type.
        /// </summary>
        /// <typeparam name="TOptions">The type of command options.</typeparam>
        public void ClearMiddleware<TOptions>() where TOptions : CommandHandlerOptions
        {
            var optionsType = typeof(TOptions);
            if (_middlewareRegistry.TryRemove(optionsType, out var middlewareList))
            {
                _logger.LogInformation("Cleared {MiddlewareCount} validation middleware components for {OptionsType}",
                    middlewareList.Count, optionsType.Name);
            }
        }

        /// <summary>
        /// Gets all registered middleware types for debugging purposes.
        /// </summary>
        /// <returns>A dictionary of options types and their registered middleware.</returns>
        public Dictionary<Type, List<string>> GetRegisteredMiddleware()
        {
            var result = new Dictionary<Type, List<string>>();

            foreach (var kvp in _middlewareRegistry)
            {
                var middlewareNames = kvp.Value.Select(m => m.GetType().Name).ToList();
                result[kvp.Key] = middlewareNames;
            }

            return result;
        }
    }
}