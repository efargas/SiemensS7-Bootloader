using System;
using System.Diagnostics.CodeAnalysis;

namespace S7.Utils
{
    /// <summary>
    /// Represents the result of an operation that can either succeed or fail.
    /// This pattern helps avoid exceptions for expected error conditions and provides
    /// a more functional approach to error handling.
    /// </summary>
    /// <typeparam name="T">The type of the success value.</typeparam>
    public readonly struct Result<T>
    {
        private readonly T? _value;
        private readonly Exception? _error;

        /// <summary>
        /// Gets a value indicating whether the operation was successful.
        /// </summary>
        [MemberNotNullWhen(true, nameof(_value))]
        [MemberNotNullWhen(false, nameof(_error))]
        public bool IsSuccess { get; }

        /// <summary>
        /// Gets a value indicating whether the operation failed.
        /// </summary>
        public bool IsFailure => !IsSuccess;

        /// <summary>
        /// Gets the success value. Only valid when IsSuccess is true.
        /// </summary>
        public T Value => IsSuccess ? _value : throw new InvalidOperationException("Cannot access Value when Result is in failure state. Check IsSuccess first.");

        /// <summary>
        /// Gets the error. Only valid when IsFailure is true.
        /// </summary>
        public Exception Error => IsFailure ? _error : throw new InvalidOperationException("Cannot access Error when Result is in success state. Check IsFailure first.");

        private Result(T value)
        {
            _value = value;
            _error = null;
            IsSuccess = true;
        }

        private Result(Exception error)
        {
            _value = default;
            _error = error ?? throw new ArgumentNullException(nameof(error));
            IsSuccess = false;
        }

        /// <summary>
        /// Creates a successful result with the specified value.
        /// </summary>
        /// <param name="value">The success value.</param>
        /// <returns>A successful result.</returns>
        public static Result<T> Success(T value) => new(value);

        /// <summary>
        /// Creates a failed result with the specified error.
        /// </summary>
        /// <param name="error">The error that caused the failure.</param>
        /// <returns>A failed result.</returns>
        public static Result<T> Failure(Exception error) => new(error);

        /// <summary>
        /// Creates a failed result with the specified error message.
        /// </summary>
        /// <param name="errorMessage">The error message.</param>
        /// <returns>A failed result.</returns>
        public static Result<T> Failure(string errorMessage) => new(new InvalidOperationException(errorMessage));

        /// <summary>
        /// Executes the specified action based on the result state.
        /// </summary>
        /// <param name="onSuccess">Action to execute if the result is successful.</param>
        /// <param name="onFailure">Action to execute if the result is failed.</param>
        public void Match(Action<T> onSuccess, Action<Exception> onFailure)
        {
            if (IsSuccess)
                onSuccess(Value);
            else
                onFailure(Error);
        }

        /// <summary>
        /// Transforms the result using the specified functions.
        /// </summary>
        /// <typeparam name="TResult">The type of the result.</typeparam>
        /// <param name="onSuccess">Function to execute if the result is successful.</param>
        /// <param name="onFailure">Function to execute if the result is failed.</param>
        /// <returns>The transformed result.</returns>
        public TResult Match<TResult>(Func<T, TResult> onSuccess, Func<Exception, TResult> onFailure)
        {
            return IsSuccess ? onSuccess(Value) : onFailure(Error);
        }

        /// <summary>
        /// Maps the success value to a new type using the specified function.
        /// If the result is failed, returns a failed result of the new type.
        /// </summary>
        /// <typeparam name="TNew">The new type.</typeparam>
        /// <param name="mapper">The mapping function.</param>
        /// <returns>A result of the new type.</returns>
        public Result<TNew> Map<TNew>(Func<T, TNew> mapper)
        {
            return IsSuccess ? Result<TNew>.Success(mapper(Value)) : Result<TNew>.Failure(Error);
        }

        /// <summary>
        /// Binds the result to a new result-returning function.
        /// This allows chaining of operations that can fail.
        /// </summary>
        /// <typeparam name="TNew">The new type.</typeparam>
        /// <param name="binder">The binding function.</param>
        /// <returns>A result of the new type.</returns>
        public Result<TNew> Bind<TNew>(Func<T, Result<TNew>> binder)
        {
            return IsSuccess ? binder(Value) : Result<TNew>.Failure(Error);
        }

        /// <summary>
        /// Returns the value if successful, otherwise returns the specified default value.
        /// </summary>
        /// <param name="defaultValue">The default value to return on failure.</param>
        /// <returns>The value or default value.</returns>
        public T GetValueOrDefault(T defaultValue = default!)
        {
            return IsSuccess ? Value : defaultValue;
        }

        /// <summary>
        /// Implicit conversion from a value to a successful result.
        /// </summary>
        /// <param name="value">The value.</param>
        public static implicit operator Result<T>(T value) => Success(value);

        /// <summary>
        /// Implicit conversion from an exception to a failed result.
        /// </summary>
        /// <param name="error">The error.</param>
        public static implicit operator Result<T>(Exception error) => Failure(error);

        public override string ToString()
        {
            return IsSuccess ? $"Success({Value})" : $"Failure({Error.Message})";
        }
    }

    /// <summary>
    /// Represents the result of an operation that can either succeed or fail without a return value.
    /// </summary>
    public readonly struct Result
    {
        private readonly Exception? _error;

        /// <summary>
        /// Gets a value indicating whether the operation was successful.
        /// </summary>
        [MemberNotNullWhen(false, nameof(_error))]
        public bool IsSuccess { get; }

        /// <summary>
        /// Gets a value indicating whether the operation failed.
        /// </summary>
        public bool IsFailure => !IsSuccess;

        /// <summary>
        /// Gets the error. Only valid when IsFailure is true.
        /// </summary>
        public Exception Error => IsFailure ? _error : throw new InvalidOperationException("Cannot access Error when Result is in success state. Check IsFailure first.");

        private Result(Exception? error)
        {
            _error = error;
            IsSuccess = error == null;
        }

        /// <summary>
        /// Creates a successful result.
        /// </summary>
        /// <returns>A successful result.</returns>
        public static Result Success() => new(null);

        /// <summary>
        /// Creates a failed result with the specified error.
        /// </summary>
        /// <param name="error">The error that caused the failure.</param>
        /// <returns>A failed result.</returns>
        public static Result Failure(Exception error) => new(error ?? throw new ArgumentNullException(nameof(error)));

        /// <summary>
        /// Creates a failed result with the specified error message.
        /// </summary>
        /// <param name="errorMessage">The error message.</param>
        /// <returns>A failed result.</returns>
        public static Result Failure(string errorMessage) => new(new InvalidOperationException(errorMessage));

        /// <summary>
        /// Executes the specified action based on the result state.
        /// </summary>
        /// <param name="onSuccess">Action to execute if the result is successful.</param>
        /// <param name="onFailure">Action to execute if the result is failed.</param>
        public void Match(Action onSuccess, Action<Exception> onFailure)
        {
            if (IsSuccess)
                onSuccess();
            else
                onFailure(Error);
        }

        /// <summary>
        /// Transforms the result using the specified functions.
        /// </summary>
        /// <typeparam name="TResult">The type of the result.</typeparam>
        /// <param name="onSuccess">Function to execute if the result is successful.</param>
        /// <param name="onFailure">Function to execute if the result is failed.</param>
        /// <returns>The transformed result.</returns>
        public TResult Match<TResult>(Func<TResult> onSuccess, Func<Exception, TResult> onFailure)
        {
            return IsSuccess ? onSuccess() : onFailure(Error);
        }

        /// <summary>
        /// Implicit conversion from an exception to a failed result.
        /// </summary>
        /// <param name="error">The error.</param>
        public static implicit operator Result(Exception error) => Failure(error);

        public override string ToString()
        {
            return IsSuccess ? "Success" : $"Failure({Error.Message})";
        }
    }

    /// <summary>
    /// Helper methods for working with Result types.
    /// </summary>
    public static class ResultExtensions
    {
        /// <summary>
        /// Executes the specified function and wraps the result in a Result type.
        /// Any exceptions thrown are captured and returned as a failed result.
        /// </summary>
        /// <typeparam name="T">The return type.</typeparam>
        /// <param name="func">The function to execute.</param>
        /// <returns>A result containing either the return value or the exception.</returns>
        public static Result<T> Try<T>(Func<T> func)
        {
            try
            {
                return Result<T>.Success(func());
            }
            catch (Exception ex)
            {
                return Result<T>.Failure(ex);
            }
        }

        /// <summary>
        /// Executes the specified action and wraps the result in a Result type.
        /// Any exceptions thrown are captured and returned as a failed result.
        /// </summary>
        /// <param name="action">The action to execute.</param>
        /// <returns>A result indicating success or failure.</returns>
        public static Result Try(Action action)
        {
            try
            {
                action();
                return Result.Success();
            }
            catch (Exception ex)
            {
                return Result.Failure(ex);
            }
        }
    }
}