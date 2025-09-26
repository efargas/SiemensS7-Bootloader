using S7.Core.Abstractions.Commands;
using S7.Utils;
using System.Threading;
using System.Threading.Tasks;

namespace S7.Core.Abstractions.Middleware
{
    /// <summary>
    /// Interface for validation middleware that validates command options before execution.
    /// </summary>
    /// <typeparam name="TOptions">The type of command options to validate.</typeparam>
    public interface IValidationMiddleware<TOptions> where TOptions : CommandHandlerOptions
    {
        /// <summary>
        /// Validates the command options before execution.
        /// </summary>
        /// <param name="options">The command options to validate.</param>
        /// <param name="cancellationToken">Cancellation token for the operation.</param>
        /// <returns>A result indicating whether validation passed or failed with error details.</returns>
        Task<Result<bool>> ValidateAsync(TOptions options, CancellationToken cancellationToken = default);

        /// <summary>
        /// Gets the validation order priority. Lower values execute first.
        /// </summary>
        int Order { get; }

        /// <summary>
        /// Gets a value indicating whether this middleware should stop the pipeline on validation failure.
        /// </summary>
        bool StopOnFailure { get; }
    }
}