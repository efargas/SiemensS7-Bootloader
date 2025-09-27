#nullable enable
using Microsoft.Extensions.Logging;
using S7_Csharp_Utility.Interfaces;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;

namespace S7_Csharp_Utility.Services
{
    /// <summary>
    /// Implementation of IApplicationStateService that provides centralized state management
    /// for coordinating operations across different features of the application.
    /// This service is thread-safe and designed to be used as a singleton.
    /// </summary>
    public class ApplicationStateService : IApplicationStateService
    {
        private readonly ILogger<ApplicationStateService> _logger;
        private readonly ConcurrentDictionary<string, bool> _activeOperations;
        private readonly ConcurrentDictionary<string, Func<bool>> _stateProviders;
        private readonly object _eventLock = new object();

        /// <summary>
        /// Initializes a new instance of the ApplicationStateService class.
        /// </summary>
        /// <param name="logger">The logger instance for this service.</param>
        /// <exception cref="ArgumentNullException">Thrown when logger is null.</exception>
        public ApplicationStateService(ILogger<ApplicationStateService> logger)
        {
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
            _activeOperations = new ConcurrentDictionary<string, bool>();
            _stateProviders = new ConcurrentDictionary<string, Func<bool>>();

            _logger.LogDebug("ApplicationStateService initialized");
        }

        /// <inheritdoc />
        public bool IsAnyOperationInProgress => _activeOperations.Any(kvp => kvp.Value);

        /// <inheritdoc />
        public bool CanExecuteExploitSequence
        {
            get
            {
                // Exploit sequence can execute if no operations are in progress
                // and all registered state providers return true
                if (IsAnyOperationInProgress)
                {
                    _logger.LogDebug("Cannot execute exploit sequence: operations in progress");
                    return false;
                }

                return EvaluateStateProviders("CanExecuteExploitSequence");
            }
        }

        /// <inheritdoc />
        public bool CanExecuteMemoryDump
        {
            get
            {
                // Memory dump can execute if no operations are in progress
                // and all registered state providers return true
                if (IsAnyOperationInProgress)
                {
                    _logger.LogDebug("Cannot execute memory dump: operations in progress");
                    return false;
                }

                return EvaluateStateProviders("CanExecuteMemoryDump");
            }
        }

        /// <inheritdoc />
        public event EventHandler<ApplicationStateChangedEventArgs>? StateChanged;

        /// <inheritdoc />
        public void NotifyOperationStarted(string operationName)
        {
            if (string.IsNullOrWhiteSpace(operationName))
                throw new ArgumentException("Operation name cannot be null or whitespace.", nameof(operationName));

            _logger.LogInformation("Operation started: {OperationName}", operationName);

            _activeOperations.AddOrUpdate(operationName, true, (key, oldValue) => true);

            RaiseStateChanged(operationName, isOperationStarted: true);
        }

        /// <inheritdoc />
        public void NotifyOperationCompleted(string operationName)
        {
            if (string.IsNullOrWhiteSpace(operationName))
                throw new ArgumentException("Operation name cannot be null or whitespace.", nameof(operationName));

            _logger.LogInformation("Operation completed: {OperationName}", operationName);

            _activeOperations.AddOrUpdate(operationName, false, (key, oldValue) => false);

            RaiseStateChanged(operationName, isOperationStarted: false);
        }

        /// <inheritdoc />
        public void RegisterStateProvider(string key, Func<bool> stateProvider)
        {
            if (string.IsNullOrWhiteSpace(key))
                throw new ArgumentException("Key cannot be null or whitespace.", nameof(key));

            if (stateProvider == null)
                throw new ArgumentNullException(nameof(stateProvider));

            _logger.LogDebug("Registering state provider: {Key}", key);

            _stateProviders.AddOrUpdate(key, stateProvider, (existingKey, existingProvider) =>
            {
                _logger.LogWarning("Replacing existing state provider for key: {Key}", key);
                return stateProvider;
            });
        }

        /// <inheritdoc />
        public void UnregisterStateProvider(string key)
        {
            if (string.IsNullOrWhiteSpace(key))
                throw new ArgumentException("Key cannot be null or whitespace.", nameof(key));

            _logger.LogDebug("Unregistering state provider: {Key}", key);

            if (_stateProviders.TryRemove(key, out _))
            {
                _logger.LogDebug("Successfully unregistered state provider: {Key}", key);
            }
            else
            {
                _logger.LogWarning("Attempted to unregister non-existent state provider: {Key}", key);
            }
        }

        /// <summary>
        /// Evaluates all registered state providers and returns true if all return true.
        /// </summary>
        /// <param name="context">The context for logging purposes.</param>
        /// <returns>True if all state providers return true; otherwise, false.</returns>
        private bool EvaluateStateProviders(string context)
        {
            if (!_stateProviders.Any())
            {
                _logger.LogDebug("No state providers registered for {Context}", context);
                return true;
            }

            var failedProviders = new List<string>();

            foreach (var kvp in _stateProviders)
            {
                try
                {
                    if (!kvp.Value())
                    {
                        failedProviders.Add(kvp.Key);
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Error evaluating state provider {Key} for {Context}", kvp.Key, context);
                    failedProviders.Add(kvp.Key);
                }
            }

            if (failedProviders.Any())
            {
                _logger.LogDebug("State providers failed for {Context}: {FailedProviders}", 
                    context, string.Join(", ", failedProviders));
                return false;
            }

            return true;
        }

        /// <summary>
        /// Raises the StateChanged event in a thread-safe manner.
        /// </summary>
        /// <param name="operationName">The name of the operation that caused the state change.</param>
        /// <param name="isOperationStarted">True if the operation started; false if it completed.</param>
        private void RaiseStateChanged(string operationName, bool isOperationStarted)
        {
            try
            {
                lock (_eventLock)
                {
                    var args = new ApplicationStateChangedEventArgs(
                        operationName, 
                        isOperationStarted, 
                        IsAnyOperationInProgress);

                    StateChanged?.Invoke(this, args);

                    _logger.LogDebug("State changed event raised for operation: {OperationName}, Started: {IsStarted}, AnyInProgress: {AnyInProgress}",
                        operationName, isOperationStarted, IsAnyOperationInProgress);
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error raising StateChanged event for operation: {OperationName}", operationName);
            }
        }
    }
}