using S7_Csharp_Utility.Models;
using System.Threading.Tasks;

namespace S7_Csharp_Utility.Interfaces
{
    /// <summary>
    /// Defines a service for managing the application's overall state, including configuration and profiles.
    /// </summary>
    public interface IApplicationStateService
    {
        /// <summary>
        /// Loads the application configuration from the default location.
        /// </summary>
        /// <returns>The loaded application configuration, or null if not found.</returns>
        Task<ApplicationConfiguration?> LoadStateFromDefaultLocationAsync();

        /// <summary>
        /// Saves the current application configuration to the default location.
        /// </summary>
        /// <param name="config">The application configuration to save.</param>
        Task SaveStateToDefaultLocationAsync(ApplicationConfiguration config);

        /// <summary>
        /// Loads a device profile from a specified path.
        /// </summary>
        /// <param name="path">The path to the profile file.</param>
        /// <returns>The loaded device profile, or null if not found.</returns>
        Task<DeviceProfile?> LoadProfileAsync(string path);
    }
}