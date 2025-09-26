using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using S7.Utils;

namespace S7.Core.Abstractions.Services
{
    /// <summary>
    /// Service interface for validating application configuration using data annotations and custom validation logic.
    /// </summary>
    public interface IConfigurationValidationService
    {
        /// <summary>
        /// Validates the entire application configuration and returns validation results.
        /// </summary>
        /// <param name="cancellationToken">Cancellation token for the operation</param>
        /// <returns>A result containing validation status and any errors</returns>
        Task<Result<bool>> ValidateConfigurationAsync(CancellationToken cancellationToken = default);

        /// <summary>
        /// Validates a specific configuration section and returns validation results.
        /// </summary>
        /// <typeparam name="T">The type of configuration section to validate</typeparam>
        /// <param name="configurationSection">The configuration section to validate</param>
        /// <param name="sectionName">The name of the configuration section for logging</param>
        /// <param name="cancellationToken">Cancellation token for the operation</param>
        /// <returns>A result containing validation status and any errors</returns>
        Task<Result<bool>> ValidateConfigurationSectionAsync<T>(T configurationSection, string sectionName, CancellationToken cancellationToken = default)
            where T : class;

        /// <summary>
        /// Gets all validation errors for the current configuration.
        /// </summary>
        /// <param name="cancellationToken">Cancellation token for the operation</param>
        /// <returns>A result containing a list of validation error messages</returns>
        Task<Result<IReadOnlyList<string>>> GetValidationErrorsAsync(CancellationToken cancellationToken = default);

        /// <summary>
        /// Checks if the current configuration is valid.
        /// </summary>
        /// <param name="cancellationToken">Cancellation token for the operation</param>
        /// <returns>A result indicating whether the configuration is valid</returns>
        Task<Result<bool>> IsConfigurationValidAsync(CancellationToken cancellationToken = default);
    }
}