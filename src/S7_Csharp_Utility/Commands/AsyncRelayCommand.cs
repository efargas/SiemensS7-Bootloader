using System;
using System.Threading.Tasks;
using System.Windows.Input;
using Avalonia.Threading;

namespace S7_Csharp_Utility.Commands
{
    /// <summary>
    /// An asynchronous implementation of ICommand that provides proper async/await patterns,
    /// exception handling, and thread-safe UI updates for command operations.
    /// Prevents multiple concurrent executions and ensures UI thread safety.
    /// </summary>
    public sealed class AsyncRelayCommand : ICommand
    {
        private readonly Func<object?, Task> _execute;
        private readonly Predicate<object?>? _canExecute;
        private readonly Action<Exception>? _onException;
        private bool _isExecuting;

        /// <summary>
        /// Initializes a new instance of the <see cref="AsyncRelayCommand"/> class.
        /// </summary>
        /// <param name="execute">The asynchronous execution logic.</param>
        /// <param name="canExecute">The execution status logic. Optional.</param>
        /// <param name="onException">The exception handler. Optional.</param>
        /// <exception cref="ArgumentNullException">Thrown when execute is null.</exception>
        public AsyncRelayCommand(Func<object?, Task> execute, Predicate<object?>? canExecute = null, Action<Exception>? onException = null)
        {
            _execute = execute ?? throw new ArgumentNullException(nameof(execute));
            _canExecute = canExecute;
            _onException = onException;
        }

        /// <summary>
        /// Occurs when changes occur that affect whether or not the command should execute.
        /// </summary>
        public event EventHandler? CanExecuteChanged;

        /// <summary>
        /// Gets a value indicating whether the command is currently executing.
        /// </summary>
        public bool IsExecuting => _isExecuting;

        /// <summary>
        /// Defines the method that determines whether the command can execute in its current state.
        /// </summary>
        /// <param name="parameter">Data used by the command. Can be null.</param>
        /// <returns>true if this command can be executed; otherwise, false.</returns>
        public bool CanExecute(object? parameter)
        {
            return !_isExecuting && (_canExecute?.Invoke(parameter) ?? true);
        }

        /// <summary>
        /// Defines the method to be called when the command is invoked.
        /// Uses async void pattern for ICommand implementation with proper exception handling.
        /// </summary>
        /// <param name="parameter">Data used by the command. Can be null.</param>
        public async void Execute(object? parameter)
        {
            if (!CanExecute(parameter))
            {
                return;
            }

            try
            {
                _isExecuting = true;
                RaiseCanExecuteChanged();
                
                await _execute(parameter).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                try
                {
                    _onException?.Invoke(ex);
                }
                catch (Exception handlerEx)
                {
                    // Log exception handler failures but don't let them bubble up
                    System.Diagnostics.Debug.WriteLine($"Exception handler failed: {handlerEx}");
                }
            }
            finally
            {
                _isExecuting = false;
                RaiseCanExecuteChanged();
            }
        }

        /// <summary>
        /// Executes the command asynchronously and returns a Task for testing and advanced scenarios.
        /// </summary>
        /// <param name="parameter">Data used by the command. Can be null.</param>
        /// <returns>A task representing the asynchronous command execution.</returns>
        /// <exception cref="InvalidOperationException">Thrown when the command cannot execute.</exception>
        public async Task ExecuteAsync(object? parameter)
        {
            if (!CanExecute(parameter))
            {
                throw new InvalidOperationException("Command cannot execute in its current state.");
            }

            try
            {
                _isExecuting = true;
                RaiseCanExecuteChanged();
                
                await _execute(parameter).ConfigureAwait(false);
            }
            finally
            {
                _isExecuting = false;
                RaiseCanExecuteChanged();
            }
        }

        /// <summary>
        /// Raises the CanExecuteChanged event to indicate that the return value of the CanExecute
        /// method has changed. Ensures the event is raised on the UI thread for proper data binding updates.
        /// </summary>
        public void RaiseCanExecuteChanged()
        {
            // Ensure this is run on the UI thread for proper data binding
            if (Dispatcher.UIThread.CheckAccess())
            {
                CanExecuteChanged?.Invoke(this, EventArgs.Empty);
            }
            else
            {
                Dispatcher.UIThread.Post(() => CanExecuteChanged?.Invoke(this, EventArgs.Empty));
            }
        }
    }
}