using S7.Core.Abstractions.Commands;
using S7.Utils;
using System.Threading;
using System.Threading.Tasks;

namespace S7.Core.Abstractions.Middleware
{
    /// <summary>
    /// Interface for validation pipeline that orchestrates multiple validation middleware components.
    /// </summary>
    public interface IValidationPipeline
    {
        /// <summary>
        /// Executes the validation pipeline for the specified command options.
        /// </summary>
        /// <typeparam name="TOptions">The type of command options to validate.</typeparam>
        /// <param name="options">The command options to validate.</param>
        /// <param name="cancellationToken">Cancellation token for the operation.</param>
        /// <returns>A result indicating whether all validations passed or failed with aggregated error details.</returns>
        Task<Result<ValidationPipelineResult>> ExecuteAsync<TOptions>(TOptions options, CancellationToken cancellationToken = default) 
            where TOptions : CommandHandlerOptions;

        /// <summary>
        /// Registers a validation middleware for a specific command options type.
        /// </summary>
        /// <typeparam name="TOptions">The type of command options.</typeparam>
        /// <param name="middleware">The validation middleware to register.</param>
        void RegisterMiddleware<TOptions>(IValidationMiddleware<TOptions> middleware) 
            where TOptions : CommandHandlerOptions;
    }

    /// <summary>
    /// Result of validation pipeline execution.
    /// </summary>
    public class ValidationPipelineResult
    {
        /// <summary>
        /// Gets or sets a value indicating whether all validations passed.
        /// </summary>
        public bool IsValid { get; set; }

        /// <summary>
        /// Gets or sets the validation errors from all middleware components.
        /// </summary>
        public List<ValidationError> Errors { get; set; } = new List<ValidationError>();

        /// <summary>
        /// Gets or sets the number of middleware components that were executed.
        /// </summary>
        public int MiddlewareExecuted { get; set; }

        /// <summary>
        /// Gets or sets the total execution time for the validation pipeline.
        /// </summary>
        public TimeSpan ExecutionTime { get; set; }
    }

    /// <summary>
    /// Represents a validation error from middleware.
    /// </summary>
    public class ValidationError
    {
        /// <summary>
        /// Gets or sets the property name that failed validation.
        /// </summary>
        public string PropertyName { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets the error message.
        /// </summary>
        public string ErrorMessage { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets the middleware that generated this error.
        /// </summary>
        public string MiddlewareName { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets the severity level of the error.
        /// </summary>
        public ValidationSeverity Severity { get; set; } = ValidationSeverity.Error;
    }

    /// <summary>
    /// Validation error severity levels.
    /// </summary>
    public enum ValidationSeverity
    {
        /// <summary>
        /// Information level - does not prevent execution.
        /// </summary>
        Information,

        /// <summary>
        /// Warning level - may affect execution but does not prevent it.
        /// </summary>
        Warning,

        /// <summary>
        /// Error level - prevents execution.
        /// </summary>
        Error,

        /// <summary>
        /// Critical level - prevents execution and requires immediate attention.
        /// </summary>
        Critical
    }
}