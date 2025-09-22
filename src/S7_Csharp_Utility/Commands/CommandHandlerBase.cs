using System;
using System.Threading.Tasks;

namespace S7_Csharp_Utility.Commands
{
    /// <summary>
    /// Base class for command handlers providing common functionality and error handling patterns.
    /// Implements the Command Handler pattern with generic base classes.
    /// </summary>
    /// <typeparam name="TOptions">The type of options/parameters for the command.</typeparam>
    public abstract class CommandHandlerBase<TOptions>
    {
        /// <summary>
        /// Executes the command with the specified options.
        /// </summary>
        /// <param name="options">The command options/parameters.</param>
        /// <returns>A task representing the asynchronous command execution.</returns>
        /// <exception cref="ArgumentNullException">Thrown when options is null.</exception>
        public async Task ExecuteAsync(TOptions options)
        {
            ArgumentNullException.ThrowIfNull(options);

            try
            {
                await ValidateOptionsAsync(options).ConfigureAwait(false);
                await ExecuteInternalAsync(options).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                await HandleExceptionAsync(ex, options).ConfigureAwait(false);
                throw;
            }
        }

        /// <summary>
        /// Validates the command options before execution.
        /// Override this method to implement custom validation logic.
        /// </summary>
        /// <param name="options">The command options to validate.</param>
        /// <returns>A task representing the asynchronous validation operation.</returns>
        /// <exception cref="ArgumentException">Thrown when validation fails.</exception>
        protected virtual Task ValidateOptionsAsync(TOptions options)
        {
            // Default implementation - no validation
            return Task.CompletedTask;
        }

        /// <summary>
        /// Executes the core command logic.
        /// Override this method to implement the specific command behavior.
        /// </summary>
        /// <param name="options">The validated command options.</param>
        /// <returns>A task representing the asynchronous command execution.</returns>
        protected abstract Task ExecuteInternalAsync(TOptions options);

        /// <summary>
        /// Handles exceptions that occur during command execution.
        /// Override this method to implement custom exception handling logic.
        /// </summary>
        /// <param name="exception">The exception that occurred.</param>
        /// <param name="options">The command options that were being processed.</param>
        /// <returns>A task representing the asynchronous exception handling operation.</returns>
        protected virtual Task HandleExceptionAsync(Exception exception, TOptions options)
        {
            // Default implementation - log the exception
            System.Diagnostics.Debug.WriteLine($"Command execution failed: {exception}");
            return Task.CompletedTask;
        }
    }

    /// <summary>
    /// Base class for command handlers that return a result.
    /// </summary>
    /// <typeparam name="TOptions">The type of options/parameters for the command.</typeparam>
    /// <typeparam name="TResult">The type of result returned by the command.</typeparam>
    public abstract class CommandHandlerBase<TOptions, TResult>
    {
        /// <summary>
        /// Executes the command with the specified options and returns a result.
        /// </summary>
        /// <param name="options">The command options/parameters.</param>
        /// <returns>A task representing the asynchronous command execution with result.</returns>
        /// <exception cref="ArgumentNullException">Thrown when options is null.</exception>
        public async Task<TResult> ExecuteAsync(TOptions options)
        {
            ArgumentNullException.ThrowIfNull(options);

            try
            {
                await ValidateOptionsAsync(options).ConfigureAwait(false);
                return await ExecuteInternalAsync(options).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                await HandleExceptionAsync(ex, options).ConfigureAwait(false);
                throw;
            }
        }

        /// <summary>
        /// Validates the command options before execution.
        /// Override this method to implement custom validation logic.
        /// </summary>
        /// <param name="options">The command options to validate.</param>
        /// <returns>A task representing the asynchronous validation operation.</returns>
        /// <exception cref="ArgumentException">Thrown when validation fails.</exception>
        protected virtual Task ValidateOptionsAsync(TOptions options)
        {
            // Default implementation - no validation
            return Task.CompletedTask;
        }

        /// <summary>
        /// Executes the core command logic and returns a result.
        /// Override this method to implement the specific command behavior.
        /// </summary>
        /// <param name="options">The validated command options.</param>
        /// <returns>A task representing the asynchronous command execution with result.</returns>
        protected abstract Task<TResult> ExecuteInternalAsync(TOptions options);

        /// <summary>
        /// Handles exceptions that occur during command execution.
        /// Override this method to implement custom exception handling logic.
        /// </summary>
        /// <param name="exception">The exception that occurred.</param>
        /// <param name="options">The command options that were being processed.</param>
        /// <returns>A task representing the asynchronous exception handling operation.</returns>
        protected virtual Task HandleExceptionAsync(Exception exception, TOptions options)
        {
            // Default implementation - log the exception
            System.Diagnostics.Debug.WriteLine($"Command execution failed: {exception}");
            return Task.CompletedTask;
        }
    }
}