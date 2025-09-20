using System;
using System.Threading.Tasks;
using System.Windows.Input;
using Avalonia.Threading;

namespace S7_Csharp_Utility.Commands
{
    /// <summary>
    /// An asynchronous command whose sole purpose is to relay its functionality to other
    /// objects by invoking delegates. Provides support for async/await operations while
    /// preventing multiple concurrent executions.
    /// </summary>
    public class AsyncRelayCommand : ICommand
    {
        private readonly Func<object?, Task> _execute;
        private readonly Predicate<object?>? _canExecute;
        private readonly Action<Exception>? _onException;
        private bool _isExecuting;

        public AsyncRelayCommand(Func<object?, Task> execute, Predicate<object?>? canExecute = null, Action<Exception>? onException = null)
        {
            _execute = execute ?? throw new ArgumentNullException(nameof(execute));
            _canExecute = canExecute;
            _onException = onException;
        }

        public event EventHandler? CanExecuteChanged;

        public bool CanExecute(object? parameter)
        {
            return !_isExecuting && (_canExecute == null || _canExecute(parameter));
        }

        public async void Execute(object? parameter)
        {
            if (CanExecute(parameter))
            {
                _isExecuting = true;
                RaiseCanExecuteChanged();
                try
                {
                    await _execute(parameter);
                }
                catch (Exception ex)
                {
                    _onException?.Invoke(ex);
                }
                finally
                {
                    _isExecuting = false;
                    RaiseCanExecuteChanged();
                }
            }
        }

        /// <summary>
        /// Method used to raise the <see cref="CanExecuteChanged"/> event
        /// to indicate that the return value of the <see cref="CanExecute"/>
        /// method has changed. Ensures the event is raised on the UI thread.
        /// </summary>
        public void RaiseCanExecuteChanged()
        {
            // Ensure this is run on the UI thread
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