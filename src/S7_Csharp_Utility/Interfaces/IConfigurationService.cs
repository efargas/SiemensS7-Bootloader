using S7_Csharp_Utility.Models;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace S7_Csharp_Utility.Interfaces
{
    /// <summary>
    /// Defines a service for handling application configuration and device profile management.
    /// </summary>
    public interface IConfigurationService
    {
        /// <summary>
        /// Saves the application configuration to the specified file path.
        /// </summary>
        Task SaveConfigurationAsync(ApplicationConfiguration config, string filePath);

        /// <summary>
        /// Loads the application configuration from the specified file path.
        /// </summary>
        Task<ApplicationConfiguration?> LoadConfigurationAsync(string filePath);

        /// <summary>
        /// Saves a device profile to the specified file path.
        /// </summary>
        Task SaveProfileAsync(DeviceProfile profile, string filePath);

        /// <summary>
        /// Loads a device profile from the specified file path.
        /// </summary>
        Task<DeviceProfile?> LoadProfileAsync(string filePath);

        /// <summary>
        /// Gets the directory path where device profiles are stored.
        /// </summary>
        string GetProfilesDirectory();

        /// <summary>
        /// Loads all device profiles from the profiles directory.
        /// </summary>
        Task<List<DeviceProfile>> LoadAllProfilesAsync();

        /// <summary>
        /// Deletes a device profile file from the file system.
        /// </summary>
        Task DeleteProfileAsync(string filePath);
    }
}