using System;
using System.Collections.Generic;
using System.Linq;

namespace S7.Core.Abstractions.Commands
{
    /// <summary>
    /// Represents the result of a command execution.
    /// </summary>
    /// <typeparam name="T">The type of data returned by the command</typeparam>
    public class CommandResult<T>
    {
        /// <summary>
        /// Gets a value indicating whether the command execution was successful.
        /// </summary>
        public bool IsSuccess { get; init; }

        /// <summary>
        /// Gets the data returned by the command execution.
        /// </summary>
        public T? Data { get; init; }

        /// <summary>
        /// Gets the error message if the command execution failed.
        /// </summary>
        public string? ErrorMessage { get; init; }

        /// <summary>
        /// Gets the exception that caused the command execution to fail.
        /// </summary>
        public Exception? Exception { get; init; }

        /// <summary>
        /// Gets the validation errors if the command validation failed.
        /// </summary>
        public IReadOnlyList<string> ValidationErrors { get; init; } = Array.Empty<string>();

        /// <summary>
        /// Gets the correlation ID for tracking this command execution.
        /// </summary>
        public string? CorrelationId { get; init; }

        /// <summary>
        /// Creates a successful command result with data.
        /// </summary>
        /// <param name="data">The data to return</param>
        /// <param name="correlationId">The correlation ID for tracking</param>
        /// <returns>A successful command result</returns>
        public static CommandResult<T> Success(T data, string? correlationId = null)
        {
            return new CommandResult<T>
            {
                IsSuccess = true,
                Data = data,
                CorrelationId = correlationId
            };
        }

        /// <summary>
        /// Creates a failed command result with an error message.
        /// </summary>
        /// <param name="errorMessage">The error message</param>
        /// <param name="correlationId">The correlation ID for tracking</param>
        /// <returns>A failed command result</returns>
        public static CommandResult<T> Failure(string errorMessage, string? correlationId = null)
        {
            return new CommandResult<T>
            {
                IsSuccess = false,
                ErrorMessage = errorMessage,
                CorrelationId = correlationId
            };
        }

        /// <summary>
        /// Creates a failed command result from an exception.
        /// </summary>
        /// <param name="exception">The exception that caused the failure</param>
        /// <param name="correlationId">The correlation ID for tracking</param>
        /// <returns>A failed command result</returns>
        public static CommandResult<T> FromException(Exception exception, string? correlationId = null)
        {
            return new CommandResult<T>
            {
                IsSuccess = false,
                ErrorMessage = exception.Message,
                Exception = exception,
                CorrelationId = correlationId
            };
        }

        /// <summary>
        /// Creates a failed command result from validation errors.
        /// </summary>
        /// <param name="validationErrors">The validation errors</param>
        /// <param name="correlationId">The correlation ID for tracking</param>
        /// <returns>A failed command result</returns>
        public static CommandResult<T> ValidationFailure(IEnumerable<string> validationErrors, string? correlationId = null)
        {
            var errors = validationErrors.ToList();
            return new CommandResult<T>
            {
                IsSuccess = false,
                ErrorMessage = errors.Count == 1 ? errors[0] : $"Validation failed with {errors.Count} errors",
                ValidationErrors = errors,
                CorrelationId = correlationId
            };
        }
    }

    /// <summary>
    /// Non-generic command result for commands that don't return data.
    /// </summary>
    public class CommandResult : CommandResult<object>
    {
        /// <summary>
        /// Creates a successful command result without data.
        /// </summary>
        /// <param name="correlationId">The correlation ID for tracking</param>
        /// <returns>A successful command result</returns>
        public static CommandResult Success(string? correlationId = null)
        {
            return new CommandResult
            {
                IsSuccess = true,
                CorrelationId = correlationId
            };
        }

        /// <summary>
        /// Creates a failed command result with an error message.
        /// </summary>
        /// <param name="errorMessage">The error message</param>
        /// <param name="correlationId">The correlation ID for tracking</param>
        /// <returns>A failed command result</returns>
        public static new CommandResult Failure(string errorMessage, string? correlationId = null)
        {
            return new CommandResult
            {
                IsSuccess = false,
                ErrorMessage = errorMessage,
                CorrelationId = correlationId
            };
        }

        /// <summary>
        /// Creates a failed command result from an exception.
        /// </summary>
        /// <param name="exception">The exception that caused the failure</param>
        /// <param name="correlationId">The correlation ID for tracking</param>
        /// <returns>A failed command result</returns>
        public static new CommandResult FromException(Exception exception, string? correlationId = null)
        {
            return new CommandResult
            {
                IsSuccess = false,
                ErrorMessage = exception.Message,
                Exception = exception,
                CorrelationId = correlationId
            };
        }

        /// <summary>
        /// Creates a failed command result from validation errors.
        /// </summary>
        /// <param name="validationErrors">The validation errors</param>
        /// <param name="correlationId">The correlation ID for tracking</param>
        /// <returns>A failed command result</returns>
        public static new CommandResult ValidationFailure(IEnumerable<string> validationErrors, string? correlationId = null)
        {
            var errors = validationErrors.ToList();
            return new CommandResult
            {
                IsSuccess = false,
                ErrorMessage = errors.Count == 1 ? errors[0] : $"Validation failed with {errors.Count} errors",
                ValidationErrors = errors,
                CorrelationId = correlationId
            };
        }
    }
}