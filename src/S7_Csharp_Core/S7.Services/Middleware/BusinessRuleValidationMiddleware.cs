using Microsoft.Extensions.Logging;
using S7.Core.Abstractions.Commands;
using S7.Core.Abstractions.Middleware;
using S7.Utils;
using System.Threading;
using System.Threading.Tasks;

namespace S7.Services.Middleware
{
    /// <summary>
    /// Validation middleware that validates command options using custom business rules.
    /// </summary>
    /// <typeparam name="TOptions">The type of command options to validate.</typeparam>
    public class BusinessRuleValidationMiddleware<TOptions>(ILogger<BusinessRuleValidationMiddleware<TOptions>> logger) 
        : IValidationMiddleware<TOptions> where TOptions : CommandHandlerOptions
    {
        private readonly ILogger<BusinessRuleValidationMiddleware<TOptions>> _logger = logger ?? throw new ArgumentNullException(nameof(logger));

        /// <summary>
        /// Gets the validation order priority. Business rule validation runs after data annotations.
        /// </summary>
        public int Order => 20;

        /// <summary>
        /// Gets a value indicating whether this middleware should stop the pipeline on validation failure.
        /// Business rule failures should stop the pipeline.
        /// </summary>
        public bool StopOnFailure => true;

        /// <summary>
        /// Validates the command options using custom business rules.
        /// </summary>
        /// <param name="options">The command options to validate.</param>
        /// <param name="cancellationToken">Cancellation token for the operation.</param>
        /// <returns>A result indicating whether validation passed or failed with error details.</returns>
        public Task<Result<bool>> ValidateAsync(TOptions options, CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(options);

            try
            {
                _logger.LogDebug("Starting business rule validation for {OptionsType} with CorrelationId {CorrelationId}",
                    typeof(TOptions).Name, options.CorrelationId);

                var validationErrors = new List<string>();

                // Validate common business rules for all command options
                ValidateCommonBusinessRules(options, validationErrors);

                // Validate specific business rules based on options type
                ValidateSpecificBusinessRules(options, validationErrors);

                if (!validationErrors.Any())
                {
                    _logger.LogDebug("Business rule validation passed for {OptionsType}", typeof(TOptions).Name);
                    return Task.FromResult(Result<bool>.Success(true));
                }

                var aggregatedError = string.Join("; ", validationErrors);

                _logger.LogWarning("Business rule validation failed for {OptionsType}: {ValidationErrors}",
                    typeof(TOptions).Name, aggregatedError);

                return Task.FromResult(Result<bool>.Failure($"Business rule validation failed: {aggregatedError}"));
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Unexpected error during business rule validation for {OptionsType}",
                    typeof(TOptions).Name);

                return Task.FromResult(Result<bool>.Failure($"Business rule validation error: {ex.Message}"));
            }
        }

        /// <summary>
        /// Validates common business rules that apply to all command options.
        /// </summary>
        /// <param name="options">The command options to validate.</param>
        /// <param name="validationErrors">List to collect validation errors.</param>
        private void ValidateCommonBusinessRules(TOptions options, List<string> validationErrors)
        {
            // Validate correlation ID format
            if (string.IsNullOrWhiteSpace(options.CorrelationId))
            {
                validationErrors.Add("CorrelationId cannot be null or empty");
            }
            else if (options.CorrelationId.Length > 100)
            {
                validationErrors.Add("CorrelationId cannot exceed 100 characters");
            }

            // Validate timeout values
            if (options.TimeoutMs <= 0)
            {
                validationErrors.Add("TimeoutMs must be greater than 0");
            }
            else if (options.TimeoutMs > 3600000) // 1 hour max
            {
                validationErrors.Add("TimeoutMs cannot exceed 1 hour (3600000 ms)");
            }

            // Validate retry policy if present
            if (options.RetryPolicy != null)
            {
                if (options.RetryPolicy.MaxRetries < 0)
                {
                    validationErrors.Add("RetryPolicy.MaxRetries cannot be negative");
                }
                else if (options.RetryPolicy.MaxRetries > 10)
                {
                    validationErrors.Add("RetryPolicy.MaxRetries cannot exceed 10");
                }

                if (options.RetryPolicy.DelayMs <= 0)
                {
                    validationErrors.Add("RetryPolicy.DelayMs must be greater than 0");
                }
                else if (options.RetryPolicy.DelayMs > 60000) // 1 minute max
                {
                    validationErrors.Add("RetryPolicy.DelayMs cannot exceed 1 minute (60000 ms)");
                }
            }
        }

        /// <summary>
        /// Validates specific business rules based on the command options type.
        /// </summary>
        /// <param name="options">The command options to validate.</param>
        /// <param name="validationErrors">List to collect validation errors.</param>
        private void ValidateSpecificBusinessRules(TOptions options, List<string> validationErrors)
        {
            switch (options)
            {
                case MemoryDumpOptions memoryDumpOptions:
                    ValidateMemoryDumpBusinessRules(memoryDumpOptions, validationErrors);
                    break;

                case StagerInstallOptions stagerInstallOptions:
                    ValidateStagerInstallBusinessRules(stagerInstallOptions, validationErrors);
                    break;

                default:
                    _logger.LogDebug("No specific business rules defined for {OptionsType}", typeof(TOptions).Name);
                    break;
            }
        }

        /// <summary>
        /// Validates business rules specific to memory dump operations.
        /// </summary>
        /// <param name="options">The memory dump options to validate.</param>
        /// <param name="validationErrors">List to collect validation errors.</param>
        private void ValidateMemoryDumpBusinessRules(MemoryDumpOptions options, List<string> validationErrors)
        {
            // Validate memory address alignment
            if (options.StartAddress % 4 != 0)
            {
                validationErrors.Add("StartAddress must be 4-byte aligned for optimal performance");
            }

            // Validate length alignment
            if (options.Length % 4 != 0)
            {
                validationErrors.Add("Length should be 4-byte aligned for optimal performance");
            }

            // Validate chunk size
            if (options.ChunkSize > 0 && options.ChunkSize > options.Length)
            {
                validationErrors.Add("ChunkSize cannot be larger than total Length");
            }

            // Validate output path
            if (!string.IsNullOrEmpty(options.OutputPath))
            {
                try
                {
                    var directory = Path.GetDirectoryName(options.OutputPath);
                    if (!string.IsNullOrEmpty(directory) && !Directory.Exists(directory))
                    {
                        validationErrors.Add($"Output directory does not exist: {directory}");
                    }
                }
                catch (Exception ex)
                {
                    validationErrors.Add($"Invalid output path: {ex.Message}");
                }
            }
        }

        /// <summary>
        /// Validates business rules specific to stager installation operations.
        /// </summary>
        /// <param name="options">The stager install options to validate.</param>
        /// <param name="validationErrors">List to collect validation errors.</param>
        private void ValidateStagerInstallBusinessRules(StagerInstallOptions options, List<string> validationErrors)
        {
            // Validate payload file exists
            if (!string.IsNullOrEmpty(options.PayloadPath) && !File.Exists(options.PayloadPath))
            {
                validationErrors.Add($"Payload file does not exist: {options.PayloadPath}");
            }

            // Validate target address range
            if (options.TargetAddress < 0x1000)
            {
                validationErrors.Add("TargetAddress should be above 0x1000 to avoid system memory regions");
            }

            // Validate max payload size
            if (options.MaxPayloadSize > 0 && !string.IsNullOrEmpty(options.PayloadPath) && File.Exists(options.PayloadPath))
            {
                var fileInfo = new FileInfo(options.PayloadPath);
                if (fileInfo.Length > options.MaxPayloadSize)
                {
                    validationErrors.Add($"Payload file size ({fileInfo.Length} bytes) exceeds MaxPayloadSize ({options.MaxPayloadSize} bytes)");
                }
            }

            // Validate backup configuration
            if (options.CreateBackup && string.IsNullOrEmpty(options.BackupFilePath))
            {
                validationErrors.Add("BackupFilePath is required when CreateBackup is enabled");
            }

            // Validate power cycling configuration
            if (options.PowerCycleBeforeInstall && options.PowerCycleDelayMs <= 0)
            {
                validationErrors.Add("PowerCycleDelayMs must be greater than 0 when PowerCycleBeforeInstall is enabled");
            }
        }
    }
}