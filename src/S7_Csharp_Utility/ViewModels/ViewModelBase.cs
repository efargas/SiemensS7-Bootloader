using System;
using System.Collections;
using System.Collections.Generic;
using System.ComponentModel;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Runtime.CompilerServices;

namespace S7_Csharp_Utility.ViewModels
{
    /// <summary>
    /// A base class for view models that implements INotifyPropertyChanged and INotifyDataErrorInfo.
    /// </summary>
    public class ViewModelBase : INotifyPropertyChanged, INotifyDataErrorInfo
    {
        private readonly Dictionary<string, List<string>> _errors = new Dictionary<string, List<string>>();

        /// <summary>
        /// Occurs when a property value changes.
        /// </summary>
        public event PropertyChangedEventHandler? PropertyChanged;
        /// <summary>
        /// Occurs when the validation errors have changed for a property or for the entire entity.
        /// </summary>
        public event EventHandler<DataErrorsChangedEventArgs>? ErrorsChanged;

        /// <summary>
        /// Gets a value that indicates whether the entity has validation errors.
        /// </summary>
        public bool HasErrors => _errors.Any();

        /// <summary>
        /// Gets the validation errors for a specified property or for the entire entity.
        /// </summary>
        /// <param name="propertyName">The name of the property to retrieve validation errors for; or null or Empty, to retrieve entity-level errors.</param>
        /// <returns>The validation errors for the property or entity.</returns>
        public IEnumerable GetErrors(string? propertyName)
        {
            if (string.IsNullOrEmpty(propertyName) || !_errors.ContainsKey(propertyName))
                return Enumerable.Empty<string>();
            return _errors[propertyName];
        }

        /// <summary>
        /// Raises the PropertyChanged event in a thread-safe manner.
        /// </summary>
        /// <param name="propertyName">The name of the property that changed.</param>
        protected void OnPropertyChanged([CallerMemberName] string? propertyName = null)
        {
            Action action = () =>
            {
                PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
                ValidateProperty(propertyName);
            };

            if (Avalonia.Threading.Dispatcher.UIThread.CheckAccess())
            {
                action();
            }
            else
            {
                Avalonia.Threading.Dispatcher.UIThread.Post(action);
            }
        }

        /// <summary>
        /// Executes an action on the UI thread. If the current thread is the UI thread, the action is executed synchronously.
        /// </summary>
        /// <param name="action">The action to execute.</param>
        protected static void Dispatch(Action action)
        {
            if (Avalonia.Threading.Dispatcher.UIThread.CheckAccess())
            {
                action();
            }
            else
            {
                Avalonia.Threading.Dispatcher.UIThread.Post(action);
            }
        }

        /// <summary>
        /// Executes an async function on the UI thread and returns a task that completes when the function is finished.
        /// </summary>
        /// <param name="func">The async function to execute.</param>
        protected static Task DispatchAsync(Func<Task> func)
        {
            if (Avalonia.Threading.Dispatcher.UIThread.CheckAccess())
            {
                return func();
            }
            else
            {
                return Avalonia.Threading.Dispatcher.UIThread.InvokeAsync(func);
            }
        }

        /// <summary>
        /// Executes an async function with a return value on the UI thread and returns a task that completes when the function is finished.
        /// </summary>
        /// <param name="func">The async function to execute.</param>
        protected static Task<T> DispatchAsync<T>(Func<Task<T>> func)
        {
            if (Avalonia.Threading.Dispatcher.UIThread.CheckAccess())
            {
                return func();
            }
            else
            {
                return Avalonia.Threading.Dispatcher.UIThread.InvokeAsync(func);
            }
        }

        /// <summary>
        /// Validates a property.
        /// </summary>
        /// <param name="propertyName">The name of the property to validate.</param>
        protected void ValidateProperty(string? propertyName)
        {
            if (string.IsNullOrEmpty(propertyName)) return;

            var validationContext = new ValidationContext(this) { MemberName = propertyName };
            var validationResults = new List<ValidationResult>();
            Validator.TryValidateProperty(GetType().GetProperty(propertyName)?.GetValue(this), validationContext, validationResults);

            if (_errors.ContainsKey(propertyName))
                _errors.Remove(propertyName);

            if (validationResults.Any())
            {
                _errors.Add(propertyName, validationResults.Select(c => c.ErrorMessage ?? string.Empty).ToList());
            }

            ErrorsChanged?.Invoke(this, new DataErrorsChangedEventArgs(propertyName));
        }
    }
}
