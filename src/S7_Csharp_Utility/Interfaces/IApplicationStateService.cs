#nullable enable
using System;

namespace S7_Csharp_Utility.Interfaces
{
    /// <summary>
    /// Event arguments for application state changes.
    /// </summary>
    public class ApplicationStateChangedEventArgs : EventArgs
    {
        /// <summary>
        /// Gets the name of the operation that caused the state change.
        /// </summary>
        public string OperationName { get; }

        /// <summary>
        /// Gets a value indicating whether the operation started (true) or completed (false).
        /// </summary>
        public bool IsOperationStarted { get; }

        /// <summary>
        /// Gets a value indicating whether any operation is currently in progress.
        /// </summary>
        public bool IsAnyOperationInProgress { get; }

        /// <summary>
        /// Initializes a new instance of the ApplicationStateChangedEventArgs class.
        /// </summary>
        /// <param name="operationName">The name of the operation that caused the state change.</param>
        /// <param name="isOperationStarted">True if the operation started; false if it completed.</param>
        /// <param name="isAnyOperationInProgress">True if any operation is currently in progress.</param>
        public ApplicationStateChangedEventArgs(string operationName, bool isOperationStarted, bool isAnyOperationInProgress)
        {
            OperationName = operationName ?? throw new ArgumentNullException(nameof(operationName));
            IsOperationStarted = isOperationStarted;
            IsAnyOperationInProgress = isAnyOperationInProgress;
        }
    }

    /// <summary>
    /// Service for tracking and coordinating global application state across features.
    /// Provides centralized state management for operations and cross-feature coordination.
    /// </summary>
    public interface IApplicationStateService
    {
        /// <summary>
        /// Gets a value indicating whether any operation is currently in progress across all features.
        /// </summary>
        bool IsAnyOperationInProgress { get; }

        /// <summary>
        /// Gets a value indicating whether the exploit sequence can be executed based on current state.
        /// </summary>
        bool CanExecuteExploitSequence { get; }

        /// <summary>
        /// Gets a value indicating whether memory dump operations can be executed based on current state.
        /// </summary>
        bool CanExecuteMemoryDump { get; }

        /// <summary>
        /// Occurs when the application state changes due to operations starting or completing.
        /// </summary>
        event EventHandler<ApplicationStateChangedEventArgs>? StateChanged;

        /// <summary>
        /// Notifies the service that an operation has started.
        /// This will update the global application state and notify subscribers.
        /// </summary>
        /// <param name="operationName">The name of the operation that started.</param>
        /// <exception cref="ArgumentException">Thrown when operationName is null or whitespace.</exception>
        void NotifyOperationStarted(string operationName);

        /// <summary>
        /// Notifies the service that an operation has completed.
        /// This will update the global application state and notify subscribers.
        /// </summary>
        /// <param name="operationName">The name of the operation that completed.</param>
        /// <exception cref="ArgumentException">Thrown when operationName is null or whitespace.</exception>
        void NotifyOperationCompleted(string operationName);

        /// <summary>
        /// Registers a state provider function that contributes to the overall application state.
        /// State providers are functions that return boolean values indicating whether
        /// certain conditions are met for operations to proceed.
        /// </summary>
        /// <param name="key">A unique key identifying the state provider.</param>
        /// <param name="stateProvider">A function that returns the current state for this provider.</param>
        /// <exception cref="ArgumentException">Thrown when key is null or whitespace.</exception>
        /// <exception cref="ArgumentNullException">Thrown when stateProvider is null.</exception>
        void RegisterStateProvider(string key, Func<bool> stateProvider);

        /// <summary>
        /// Unregisters a previously registered state provider.
        /// </summary>
        /// <param name="key">The unique key of the state provider to unregister.</param>
        /// <exception cref="ArgumentException">Thrown when key is null or whitespace.</exception>
        void UnregisterStateProvider(string key);
    }
}