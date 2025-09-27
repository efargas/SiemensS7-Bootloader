#nullable enable
using Microsoft.Extensions.Logging;
using S7_Csharp_Utility.Interfaces;
using System;

namespace S7_Csharp_Utility.ViewModels
{
    /// <summary>
    /// Abstract base class for feature-specific ViewModels that provides common functionality
    /// for operation state management, error handling, and application state coordination.
    /// </summary>
    public abstract class FeatureViewModelBase : ViewModelBase
    {
        /// <summary>
        /// Logger instance for the feature ViewModel.
        /// </summary>
        protected readonly ILogger Logger;

        /// <summary>
        /// Application state service for coordinating state across features.
        /// </summary>
        protected readonly IApplicationStateService ApplicationStateService;

        /// <summary>
        /// Initializes a new instance of the FeatureViewModelBase class.
        /// </summary>
        /// <param name="logger">The logger instance for this feature ViewModel.</param>
        /// <param name="applicationStateService">The application state service for state coordination.</param>
        /// <exception cref="ArgumentNullException">Thrown when logger or applicationStateService is null.</exception>
        protected FeatureViewModelBase(ILogger logger, IApplicationStateService applicationStateService)
        {
            Logger = logger ?? throw new ArgumentNullException(nameof(logger));
            ApplicationStateService = applicationStateService ?? throw new ArgumentNullException(nameof(applicationStateService));
        }

        /// <summary>
        /// Notifies the application state service that an operation has started.
        /// This method should be called at the beginning of long-running operations
        /// to coordinate state across the application.
        /// </summary>
        /// <param name="operationName">The name of the operation that started.</param>
        protected virtual void NotifyOperationStarted(string operationName)
        {
            if (string.IsNullOrWhiteSpace(operationName))
                throw new ArgumentException("Operation name cannot be null or whitespace.", nameof(operationName));

            Logger.LogInformation("Starting operation: {OperationName}", operationName);
            ApplicationStateService.NotifyOperationStarted(operationName);
        }

        /// <summary>
        /// Notifies the application state service that an operation has completed.
        /// This method should be called when long-running operations finish,
        /// regardless of success or failure.
        /// </summary>
        /// <param name="operationName">The name of the operation that completed.</param>
        protected virtual void NotifyOperationCompleted(string operationName)
        {
            if (string.IsNullOrWhiteSpace(operationName))
                throw new ArgumentException("Operation name cannot be null or whitespace.", nameof(operationName));

            Logger.LogInformation("Completed operation: {OperationName}", operationName);
            ApplicationStateService.NotifyOperationCompleted(operationName);
        }

        /// <summary>
        /// Handles exceptions in a consistent manner across all feature ViewModels.
        /// This method logs the exception and provides a standardized error handling pattern.
        /// </summary>
        /// <param name="ex">The exception that occurred.</param>
        /// <param name="context">The context in which the exception occurred.</param>
        protected virtual void HandleException(Exception ex, string context)
        {
            if (ex == null)
                throw new ArgumentNullException(nameof(ex));

            if (string.IsNullOrWhiteSpace(context))
                context = "Unknown context";

            Logger.LogError(ex, "Error in {Context}: {ErrorMessage}", context, ex.Message);

            // Additional error handling can be added here, such as:
            // - Showing user-friendly error messages
            // - Reporting to error tracking services
            // - Triggering recovery mechanisms
        }

        /// <summary>
        /// Gets a value indicating whether this feature can execute operations
        /// based on the current application state.
        /// </summary>
        /// <returns>True if operations can be executed; otherwise, false.</returns>
        protected virtual bool CanExecuteOperations()
        {
            return !ApplicationStateService.IsAnyOperationInProgress;
        }
    }
}