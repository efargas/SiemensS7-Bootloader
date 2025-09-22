using System;
using System.Collections.Generic;
using System.Linq;

namespace S7.Core.Commands
{
    /// <summary>
    /// Represents the result of a command execution.
    /// </summary>
    public class CommandResult
    {
        /// <summary>
        /// Gets a value indicating whether the command was successful.
        /// </summary>
        public bool IsSuccess { get; private set; }

        /// <summary>
        /// Gets the error message if the command failed.
        /// </summary>
        public string? ErrorMessage { get; private set; }

        /// <summary>
        /// Gets any additional data returned by the command.
        /// </summary>
        public object? Data { get; private set; }

        /// <summary>
        /// Gets validation errors if any occurred.
        /// </summary>
        public IReadOnlyList<string> ValidationErrors { get; private set; } = Array.Empty<string>();

        private CommandResult() { }

        /// <summary>
        /// Creates a successful command result.
        /// </summary>
        /// <param name="data">Optional data to include with the result</param>
        /// <returns>A successful command result</returns>
        public static CommandResult Success(object? data = null)
        {
            return new CommandResult
            {
                IsSuccess = true,
                Data = data
            };
        }

        /// <summary>
        /// Creates a failed command result with an error message.
        /// </summary>
        /// <param name="errorMessage">The error message</param>
        /// <returns>A failed command result</returns>
        public static CommandResult Failure(string errorMessage)
        {
            return new CommandResult
            {
                IsSuccess = false,
                ErrorMessage = errorMessage ?? throw new ArgumentNullException(nameof(errorMessage))
            };
        }

        /// <summary>
        /// Creates a failed command result with validation errors.
        /// </summary>
        /// <param name="validationErrors">The validation errors</param>
        /// <returns>A failed command result</returns>
        public static CommandResult ValidationFailure(IEnumerable<string> validationErrors)
        {
            var errors = validationErrors?.ToList() ?? throw new ArgumentNullException(nameof(validationErrors));
            
            return new CommandResult
            {
                IsSuccess = false,
                ErrorMessage = "Validation failed",
                ValidationErrors = errors.AsReadOnly()
            };
        }

        /// <summary>
        /// Creates a failed command result from an exception.
        /// </summary>
        /// <param name="exception">The exception that caused the failure</param>
        /// <returns>A failed command result</returns>
        public static CommandResult FromException(Exception exception)
        {
            return new CommandResult
            {
                IsSuccess = false,
                ErrorMessage = exception?.Message ?? "An unknown error occurred"
            };
        }
    }

    /// <summary>
    /// Represents the result of a command execution with typed data.
    /// </summary>
    /// <typeparam name="T">The type of data returned by the command</typeparam>
    public class CommandResult<T> : CommandResult
    {
        /// <summary>
        /// Gets the typed data returned by the command.
        /// </summary>
        public new T? Data { get; private set; }

        private CommandResult() { }

        /// <summary>
        /// Creates a successful command result with typed data.
        /// </summary>
        /// <param name="data">The data to include with the result</param>
        /// <returns>A successful command result</returns>
        public static CommandResult<T> Success(T data)
        {
            return new CommandResult<T>
            {
                IsSuccess = true,
                Data = data
            };
        }

        /// <summary>
        /// Creates a failed command result with an error message.
        /// </summary>
        /// <param name="errorMessage">The error message</param>
        /// <returns>A failed command result</returns>
        public static new CommandResult<T> Failure(string errorMessage)
        {
            return new CommandResult<T>
            {
                IsSuccess = false,
                ErrorMessage = errorMessage ?? throw new ArgumentNullException(nameof(errorMessage))
            };
        }

        /// <summary>
        /// Creates a failed command result with validation errors.
        /// </summary>
        /// <param name="validationErrors">The validation errors</param>
        /// <returns>A failed command result</returns>
        public static new CommandResult<T> ValidationFailure(IEnumerable<string> validationErrors)
        {
            var errors = validationErrors?.ToList() ?? throw new ArgumentNullException(nameof(validationErrors));
            
            return new CommandResult<T>
            {
                IsSuccess = false,
                ErrorMessage = "Validation failed",
                ValidationErrors = errors.AsReadOnly()
            };
        }

        /// <summary>
        /// Creates a failed command result from an exception.
        /// </summary>
        /// <param name="exception">The exception that caused the failure</param>
        /// <returns>A failed command result</returns>
        public static new CommandResult<T> FromException(Exception exception)
        {
            return new CommandResult<T>
            {
                IsSuccess = false,
                ErrorMessage = exception?.Message ?? "An unknown error occurred"
            };
        }
    }
}