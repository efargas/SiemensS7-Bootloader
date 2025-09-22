using System;
using System.Threading;
using System.Threading.Tasks;

namespace S7.Core.Commands
{
    /// <summary>
    /// Defines a contract for handling commands with options and returning results.
    /// </summary>
    /// <typeparam name="TOptions">The type of options required for the command</typeparam>
    public interface ICommandHandler<TOptions>
    {
        /// <summary>
        /// Handles the command asynchronously with the provided options.
        /// </summary>
        /// <param name="options">The command options</param>
        /// <param name="cancellationToken">Cancellation token for the operation</param>
        /// <returns>A command result indicating success or failure</returns>
        Task<CommandResult> HandleAsync(TOptions options, CancellationToken cancellationToken = default);
    }
}