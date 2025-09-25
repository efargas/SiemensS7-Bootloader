using System.Threading;
using System.Threading.Tasks;

namespace S7.Core.Abstractions.Commands
{
    /// <summary>
    /// Represents a command that can be executed to produce a result.
    /// </summary>
    /// <typeparam name="TResult">The type of result produced by the command</typeparam>
    public interface ICommand<TResult>
    {
        /// <summary>
        /// Gets the correlation ID for tracking this command execution.
        /// </summary>
        string CorrelationId { get; }
    }

    /// <summary>
    /// Represents a command handler that can execute commands of a specific type.
    /// </summary>
    /// <typeparam name="TCommand">The type of command to handle</typeparam>
    /// <typeparam name="TResult">The type of result produced by the command</typeparam>
    public interface ICommandHandler<in TCommand, TResult> 
        where TCommand : ICommand<TResult>
    {
        /// <summary>
        /// Handles the execution of a command asynchronously.
        /// </summary>
        /// <param name="command">The command to execute</param>
        /// <param name="cancellationToken">Cancellation token for the operation</param>
        /// <returns>A task representing the command execution result</returns>
        Task<CommandResult<TResult>> HandleAsync(TCommand command, CancellationToken cancellationToken = default);
    }
}