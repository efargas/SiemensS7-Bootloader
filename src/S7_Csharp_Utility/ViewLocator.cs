using Avalonia.Controls;
using Avalonia.Controls.Templates;
using System;

namespace S7_Csharp_Utility
{
    /// <summary>
    /// A view locator for resolving views from view models.
    /// </summary>
    public class ViewLocator : IDataTemplate
    {
        /// <summary>
        /// Builds a control for the specified data.
        /// </summary>
        /// <param name="data">The data to build a control for.</param>
        /// <returns>A control that represents the data.</returns>
        public Control Build(object? data)
        {
            if (data is null)
                return new TextBlock { Text = "No data provided" };

            var name = data.GetType().FullName!.Replace("ViewModel", "View");
            var type = Type.GetType(name);

            if (type != null)
            {
                return (Control)Activator.CreateInstance(type)!;
            }

            return new TextBlock { Text = $"Not Found: {name}" };
        }

        /// <summary>
        /// Determines whether this data template matches the specified data.
        /// </summary>
        /// <param name="data">The data to check.</param>
        /// <returns>True if the data template matches; otherwise, false.</returns>
        public bool Match(object? data)
        {
            return data is ViewModels.ViewModelBase;
        }
    }
}
