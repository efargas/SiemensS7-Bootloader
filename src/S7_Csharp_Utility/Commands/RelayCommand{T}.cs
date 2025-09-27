using System;
using System.Windows.Input;
using Avalonia.Threading;

namespace S7_Csharp_Utility.Commands
{
    /// <summary>
    /// A generic synchronous implementation of ICommand that relays its functionality to other
    /// objects by invoking delegates with strongly-typed parameters. Provides thread-safe UI updates.
    /// The default return value for the CanExecute method is 'true'.
    /// </summary>
    /// <typeparam name="T">The type of the command parameter.</typeparam>
    public sealed class RelayCommand<T> : ICommand
    {
        private readonly Action<T?> _execute;
        private readonly Predicate<T?>? _canExecute;

        /// <summary>
        /// Initializes a new instance of the <see cref="RelayCommand{T}"/> class.
        /// </summary>
        /// <param name="execute">The execution logic with strongly-typed parameter.</param>
        /// <param name="canExecute">The execution status logic with strongly-typed parameter. Optional.</param>
        /// <exception cref="ArgumentNullException">Thrown when execute is null.</exception>
        public RelayCommand(Action<T?> execute, Predicate<T?>? canExecute = null)
        {
            _execute = execute ?? throw new ArgumentNullException(nameof(execute));
            _canExecute = canExecute;
        }

        /// <summary>
        /// Occurs when changes occur that affect whether or not the command should execute.
        /// </summary>
        public event EventHandler? CanExecuteChanged;

        /// <summary>
        /// Defines the method that determines whether the command can execute in its current state.
        /// </summary>
        /// <param name="parameter">Data used by the command. Can be null.</param>
        /// <returns>true if this command can be executed; otherwise, false.</returns>
        public bool CanExecute(object? parameter)
        {
            // Handle type conversion safely
            if (parameter is T typedParameter)
            {
                return _canExecute?.Invoke(typedParameter) ?? true;
            }
            
            // Handle null case for nullable types
            if (parameter == null && (!typeof(T).IsValueType || Nullable.GetUnderlyingType(typeof(T)) != null))
            {
                return _canExecute?.Invoke(default(T)) ?? true;
            }
            
            return false;
        }

        /// <summary>
        /// Defines the method to be called when the command is invoked.
        /// </summary>
        /// <param name="parameter">Data used by the command. Can be null.</param>
        public void Execute(object? parameter)
        {
            if (CanExecute(parameter))
            {
                // Safe type conversion
                T? typedParameter = default(T);
                if (parameter is T converted)
                {
                    typedParameter = converted;
                }
                else if (parameter != null)
                {
                    try
                    {
                        typedParameter = (T)Convert.ChangeType(parameter, typeof(T));
                    }
                    catch (InvalidCastException)
                    {
                        // Use default value if conversion fails
                        typedParameter = default(T);
                    }
                }
                
                _execute(typedParameter);
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