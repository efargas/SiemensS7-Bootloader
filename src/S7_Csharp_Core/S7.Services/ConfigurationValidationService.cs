using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using S7.Core.Abstractions.Configuration;
using S7.Core.Abstractions.Services;
using S7.Utils;

namespace S7.Services
{
    /// <summary>
    /// Service for validating application configuration using data annotations and custom validation logic.
    /// </summary>
    public sealed class ConfigurationValidationService(
        IOptions<ApplicationOptions> applicationOptions,
        ILogger<ConfigurationValidationService> logger) : IConfigurationValidationService
    {
        private readonly ApplicationOptions _applicationOptions = applicationOptions?.Value ?? throw new ArgumentNullException(nameof(applicationOptions));
        private readonly ILogger<ConfigurationValidationService> _logger = logger ?? throw new ArgumentNullException(nameof(logger));

        /// <summary>
        /// Validates the entire application configuration and returns validation results.
        /// </summary>
        /// <param name="cancellationToken">Cancellation token for the operation</param>
        /// <returns>A result containing validation status and any errors</returns>
        public async Task<Result<bool>> ValidateConfigurationAsync(CancellationToken cancellationToken = default)
        {
            try
            {
                _logger.LogInformation("Starting comprehensive configuration validation");

                var validationErrors = new List<string>();

                // Validate root application options
                var rootValidationResult = await ValidateObjectAsync(_applicationOptions, "ApplicationOptions", cancellationToken);
                if (!rootValidationResult.IsSuccess)
                {
                    validationErrors.AddRange(rootValidationResult.Error.Message.Split('\n', StringSplitOptions.RemoveEmptyEntries));
                }

                // Validate PLC operation options
                if (_applicationOptions.PlcOperations != null)
                {
                    var plcValidationResult = await ValidateObjectAsync(_applicationOptions.PlcOperations, "PlcOperationOptions", cancellationToken);
                    if (!plcValidationResult.IsSuccess)
                    {
                        validationErrors.AddRange(plcValidationResult.Error.Message.Split('\n', StringSplitOptions.RemoveEmptyEntries));
                    }
                }

                // Validate memory dump options
                if (_applicationOptions.MemoryDump != null)
                {
                    var memoryDumpValidationResult = await ValidateObjectAsync(_applicationOptions.MemoryDump, "MemoryDumpOptions", cancellationToken);
                    if (!memoryDumpValidationResult.IsSuccess)
                    {
                        validationErrors.AddRange(memoryDumpValidationResult.Error.Message.Split('\n', StringSplitOptions.RemoveEmptyEntries));
                    }
                }

                // Validate stager options
                if (_applicationOptions.Stager != null)
                {
                    var stagerValidationResult = await ValidateObjectAsync(_applicationOptions.Stager, "StagerOptions", cancellationToken);
                    if (!stagerValidationResult.IsSuccess)
                    {
                        validationErrors.AddRange(stagerValidationResult.Error.Message.Split('\n', StringSplitOptions.RemoveEmptyEntries));
                    }
                }

                // Validate payload options
                if (_applicationOptions.Payload != null)
                {
                    var payloadValidationResult = await ValidateObjectAsync(_applicationOptions.Payload, "PayloadOptions", cancellationToken);
                    if (!payloadValidationResult.IsSuccess)
                    {
                        validationErrors.AddRange(payloadValidationResult.Error.Message.Split('\n', StringSplitOptions.RemoveEmptyEntries));
                    }
                }

                // Validate communication channel options
                if (_applicationOptions.CommunicationChannel != null)
                {
                    var channelValidationResult = await ValidateObjectAsync(_applicationOptions.CommunicationChannel, "CommunicationChannelOptions", cancellationToken);
                    if (!channelValidationResult.IsSuccess)
                    {
                        validationErrors.AddRange(channelValidationResult.Error.Message.Split('\n', StringSplitOptions.RemoveEmptyEntries));
                    }
                }

                // Validate power supply options
                if (_applicationOptions.PowerSupply != null)
                {
                    var powerSupplyValidationResult = await ValidateObjectAsync(_applicationOptions.PowerSupply, "PowerSupplyOptions", cancellationToken);
                    if (!powerSupplyValidationResult.IsSuccess)
                    {
                        validationErrors.AddRange(powerSupplyValidationResult.Error.Message.Split('\n', StringSplitOptions.RemoveEmptyEntries));
                    }
                }

                // Validate logging options
                if (_applicationOptions.Logging != null)
                {
                    var loggingValidationResult = await ValidateObjectAsync(_applicationOptions.Logging, "LoggingOptions", cancellationToken);
                    if (!loggingValidationResult.IsSuccess)
                    {
                        validationErrors.AddRange(loggingValidationResult.Error.Message.Split('\n', StringSplitOptions.RemoveEmptyEntries));
                    }
                }

                // Perform cross-section validation
                var crossValidationResult = await ValidateCrossSectionDependenciesAsync(cancellationToken);
                if (!crossValidationResult.IsSuccess)
                {
                    validationErrors.AddRange(crossValidationResult.Error.Message.Split('\n', StringSplitOptions.RemoveEmptyEntries));
                }

                if (validationErrors.Count > 0)
                {
                    var errorMessage = string.Join("\n", validationErrors);
                    _logger.LogError("Configuration validation failed with {ErrorCount} errors: {Errors}", validationErrors.Count, errorMessage);
                    return Result<bool>.Failure(new Exception($"Configuration validation failed:\n{errorMessage}"));
                }

                _logger.LogInformation("Configuration validation completed successfully");
                return Result<bool>.Success(true);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Unexpected error during configuration validation");
                return Result<bool>.Failure(ex);
            }
        }

        /// <summary>
        /// Validates a specific configuration section and returns validation results.
        /// </summary>
        /// <typeparam name="T">The type of configuration section to validate</typeparam>
        /// <param name="configurationSection">The configuration section to validate</param>
        /// <param name="sectionName">The name of the configuration section for logging</param>
        /// <param name="cancellationToken">Cancellation token for the operation</param>
        /// <returns>A result containing validation status and any errors</returns>
        public async Task<Result<bool>> ValidateConfigurationSectionAsync<T>(T configurationSection, string sectionName, CancellationToken cancellationToken = default)
            where T : class
        {
            try
            {
                _logger.LogDebug("Validating configuration section: {SectionName}", sectionName);

                if (configurationSection == null)
                {
                    _logger.LogWarning("Configuration section {SectionName} is null", sectionName);
                    return Result<bool>.Success(true); // Null sections are considered valid (optional)
                }

                return await ValidateObjectAsync(configurationSection, sectionName, cancellationToken);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Unexpected error validating configuration section: {SectionName}", sectionName);
                return Result<bool>.Failure(ex);
            }
        }

        /// <summary>
        /// Gets all validation errors for the current configuration.
        /// </summary>
        /// <param name="cancellationToken">Cancellation token for the operation</param>
        /// <returns>A result containing a list of validation error messages</returns>
        public async Task<Result<IReadOnlyList<string>>> GetValidationErrorsAsync(CancellationToken cancellationToken = default)
        {
            try
            {
                _logger.LogDebug("Retrieving all configuration validation errors");

                var validationResult = await ValidateConfigurationAsync(cancellationToken);
                
                if (validationResult.IsSuccess)
                {
                    return Result<IReadOnlyList<string>>.Success(new List<string>().AsReadOnly());
                }

                var errors = validationResult.Error.Message
                    .Split('\n', StringSplitOptions.RemoveEmptyEntries)
                    .Where(error => !string.IsNullOrWhiteSpace(error))
                    .ToList()
                    .AsReadOnly();

                return Result<IReadOnlyList<string>>.Success(errors);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Unexpected error retrieving validation errors");
                return Result<IReadOnlyList<string>>.Failure(ex);
            }
        }

        /// <summary>
        /// Checks if the current configuration is valid.
        /// </summary>
        /// <param name="cancellationToken">Cancellation token for the operation</param>
        /// <returns>A result indicating whether the configuration is valid</returns>
        public async Task<Result<bool>> IsConfigurationValidAsync(CancellationToken cancellationToken = default)
        {
            try
            {
                var validationResult = await ValidateConfigurationAsync(cancellationToken);
                return Result<bool>.Success(validationResult.IsSuccess);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Unexpected error checking configuration validity");
                return Result<bool>.Failure(ex);
            }
        }

        /// <summary>
        /// Validates an object using data annotations and custom validation logic.
        /// </summary>
        /// <param name="obj">The object to validate</param>
        /// <param name="objectName">The name of the object for error reporting</param>
        /// <param name="cancellationToken">Cancellation token for the operation</param>
        /// <returns>A result containing validation status and any errors</returns>
        private async Task<Result<bool>> ValidateObjectAsync(object obj, string objectName, CancellationToken cancellationToken)
        {
            await Task.Yield(); // Make method async for consistency
            cancellationToken.ThrowIfCancellationRequested();

            var validationContext = new ValidationContext(obj, serviceProvider: null, items: null);
            var validationResults = new List<ValidationResult>();

            bool isValid = Validator.TryValidateObject(obj, validationContext, validationResults, validateAllProperties: true);

            // Also validate using custom validation if the object implements IValidatableObject
            if (obj is IValidatableObject validatableObject)
            {
                var customValidationResults = validatableObject.Validate(validationContext);
                validationResults.AddRange(customValidationResults);
                isValid = isValid && !validationResults.Any();
            }

            if (!isValid)
            {
                var errorMessages = validationResults
                    .Where(vr => vr != ValidationResult.Success)
                    .Select(vr => $"{objectName}: {vr.ErrorMessage}")
                    .ToList();

                var combinedErrorMessage = string.Join("\n", errorMessages);
                _logger.LogWarning("Validation failed for {ObjectName}: {Errors}", objectName, combinedErrorMessage);
                
                return Result<bool>.Failure(new Exception(combinedErrorMessage));
            }

            _logger.LogDebug("Validation successful for {ObjectName}", objectName);
            return Result<bool>.Success(true);
        }

        /// <summary>
        /// Validates cross-section dependencies and consistency rules.
        /// </summary>
        /// <param name="cancellationToken">Cancellation token for the operation</param>
        /// <returns>A result containing validation status and any errors</returns>
        private async Task<Result<bool>> ValidateCrossSectionDependenciesAsync(CancellationToken cancellationToken)
        {
            await Task.Yield(); // Make method async for consistency
            cancellationToken.ThrowIfCancellationRequested();

            var validationErrors = new List<string>();

            try
            {
                // Validate PLC operation and communication channel consistency
                if (_applicationOptions.PlcOperations != null && _applicationOptions.CommunicationChannel != null)
                {
                    // Ensure communication channel timeout is not less than PLC operation timeout
                    if (_applicationOptions.CommunicationChannel.ConnectionTimeoutMs < _applicationOptions.PlcOperations.OperationTimeoutMs)
                    {
                        validationErrors.Add("Communication channel connection timeout cannot be less than PLC operation timeout");
                    }

                    // Validate socat configuration if enabled - check if socat binary path is configured
                    if (!string.IsNullOrWhiteSpace(_applicationOptions.CommunicationChannel.SocatBinaryPath) && 
                        !System.IO.File.Exists(_applicationOptions.CommunicationChannel.SocatBinaryPath))
                    {
                        validationErrors.Add("Socat binary path does not exist or is not accessible");
                    }
                }

                // Validate memory dump and payload consistency
                if (_applicationOptions.MemoryDump != null && _applicationOptions.Payload != null)
                {
                    // Ensure payload scan directories exist if memory dump is configured
                    if (_applicationOptions.Payload.ScanDirectories == null || _applicationOptions.Payload.ScanDirectories.Length == 0)
                    {
                        validationErrors.Add("Payload scan directories must be specified when memory dump operations are configured");
                    }
                }

                // Validate stager and power supply consistency
                if (_applicationOptions.Stager != null && _applicationOptions.Stager.EnablePowerCycling)
                {
                    if (_applicationOptions.PowerSupply == null)
                    {
                        validationErrors.Add("Power supply configuration is required when stager power cycling is enabled");
                    }
                    else if (!_applicationOptions.PowerSupply.Enabled)
                    {
                        validationErrors.Add("Power supply must be enabled when stager power cycling is configured");
                    }
                }

                // Validate logging configuration consistency
                if (_applicationOptions.Logging != null)
                {
                    // Ensure log file directory is writable if file logging is enabled
                    if (_applicationOptions.Logging.EnableFileLogging && 
                        string.IsNullOrWhiteSpace(_applicationOptions.Logging.LogFilePath))
                    {
                        validationErrors.Add("Log file path must be specified when file logging is enabled");
                    }

                    // Validate that at least one logging output is enabled
                    if (!_applicationOptions.Logging.EnableConsoleLogging && !_applicationOptions.Logging.EnableFileLogging)
                    {
                        validationErrors.Add("At least one logging output (console or file) must be enabled");
                    }
                }

                if (validationErrors.Count > 0)
                {
                    var errorMessage = string.Join("\n", validationErrors);
                    _logger.LogWarning("Cross-section validation failed: {Errors}", errorMessage);
                    return Result<bool>.Failure(new Exception(errorMessage));
                }

                _logger.LogDebug("Cross-section validation completed successfully");
                return Result<bool>.Success(true);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Unexpected error during cross-section validation");
                return Result<bool>.Failure(ex);
            }
        }
    }
}