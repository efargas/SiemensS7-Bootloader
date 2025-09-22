using Avalonia.Controls;
using S7_Csharp_Utility.Interfaces;
using System;

namespace S7_Csharp_Utility.Services
{
    /// <summary>
    /// Service for managing view-related operations and providing access to the main window.
    /// </summary>
    public sealed class ViewService : IViewService
    {
        private Window? _mainWindow;

        /// <summary>
        /// Initializes a new instance of the <see cref="ViewService"/> class.
        /// </summary>
        public ViewService()
        {
        }

        /// <summary>
        /// Sets the main window reference for the service.
        /// </summary>
        /// <param name="mainWindow">The main window instance.</param>
        /// <exception cref="ArgumentNullException">Thrown when mainWindow is null.</exception>
        public void SetMainWindow(Window mainWindow)
        {
            _mainWindow = mainWindow ?? throw new ArgumentNullException(nameof(mainWindow));
        }

        /// <summary>
        /// Gets the main window instance.
        /// </summary>
        /// <returns>The main window instance.</returns>
        /// <exception cref="InvalidOperationException">Thrown when the main window has not been set.</exception>
        public Window GetMainWindow()
        {
            return _mainWindow ?? throw new InvalidOperationException("Main window has not been set. Call SetMainWindow first.");
        }
    }
}