using System;
using System.Collections;
using System.Collections.Generic;
using System.ComponentModel;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Runtime.CompilerServices;

namespace S7_Csharp_Utility.ViewModels
{
    public class ViewModelBase : INotifyPropertyChanged, INotifyDataErrorInfo
    {
        private readonly Dictionary<string, List<string>> _errors = new Dictionary<string, List<string>>();

        public event PropertyChangedEventHandler? PropertyChanged;
        public event EventHandler<DataErrorsChangedEventArgs>? ErrorsChanged;

        public bool HasErrors => _errors.Any();

        public IEnumerable GetErrors(string? propertyName)
        {
            if (string.IsNullOrEmpty(propertyName) || !_errors.ContainsKey(propertyName))
                return Enumerable.Empty<string>();
            return _errors[propertyName];
        }

        protected void OnPropertyChanged([CallerMemberName] string? propertyName = null)
        {
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
            ValidateProperty(propertyName);
        }

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
