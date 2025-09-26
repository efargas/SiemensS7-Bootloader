using Microsoft.Extensions.Logging;
using S7.Core.Abstractions.Commands;
using S7.Core.Abstractions.Middleware;
using S7.Utils;
using System.ComponentModel.DataAnnotations;
using System.Threading;
using System.Threading.Tasks;

namespace S7.Services.Middleware
{
    /// <summary>
    /// Validation middleware that validates command options using data annotations.
    /// </summary>
    /// <typeparam name="TOptions">The type of command options to validate.</typeparam>
    public class DataAnnotationsValidationMiddleware<TOptions>(ILogger<DataAnnotationsValidationMiddleware<TOptions>> logger) 
        : IValidationMiddleware<TOptions> where TOptions : CommandHandlerOptions
    {
        private readonly ILogger<DataAnnotationsValidationMiddleware<TOptions>> _logger = logger ?? throw new ArgumentNullException(nameof(logger));

        /// <summary>
        /// Gets the validation order priority. Data annotations validation runs first.
        /// </summary>
        public int Order => 10;

        /// <summary>
        /// Gets a value indicating whether this middleware should stop the pipeline on validation failure.
        /// Data annotations failures should stop the pipeline.
        /// </summary>
        public bool StopOnFailure => true;

        /// <summary>
        /// Validates the command options using data annotations.
        /// </summary>
        /// <param name="options">The command options to validate.</param>
        /// <param name="cancellationToken">Cancellation token for the operation.</param>
        /// <returns>A result indicating whether validation passed or failed with error details.</returns>
        public Task<Result<bool>> ValidateAsync(TOptions options, CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(options);

            try
            {
                _logger.LogDebug("Starting data annotations validation for {OptionsType} with CorrelationId {CorrelationId}",
                    typeof(TOptions).Name, options.CorrelationId);

                var validationContext = new ValidationContext(options);
                var validationResults = new List<ValidationResult>();

                // Validate using data annotations
                bool isValid = Validator.TryValidateObject(options, validationContext, validationResults, validateAllProperties: true);

                if (isValid)
                {
                    _logger.LogDebug("Data annotations validation passed for {OptionsType}", typeof(TOptions).Name);
                    return Task.FromResult(Result<bool>.Success(true));
                }

                // Aggregate validation errors
                var errorMessages = validationResults
                    .Where(vr => !string.IsNullOrEmpty(vr.ErrorMessage))
                    .Select(vr => vr.ErrorMessage!)
                    .ToList();

                var aggregatedError = string.Join("; ", errorMessages);

                _logger.LogWarning("Data annotations validation failed for {OptionsType}: {ValidationErrors}",
                    typeof(TOptions).Name, aggregatedError);

                return Task.FromResult(Result<bool>.Failure($"Data annotations validation failed: {aggregatedError}"));
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Unexpected error during data annotations validation for {OptionsType}",
                    typeof(TOptions).Name);

                return Task.FromResult(Result<bool>.Failure($"Data annotations validation error: {ex.Message}"));
            }
        }
    }
}