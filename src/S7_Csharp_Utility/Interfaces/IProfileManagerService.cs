using S7_Csharp_Utility.Models;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace S7_Csharp_Utility.Interfaces
{
    /// <summary>
    /// Defines a service for managing device profiles.
    /// </summary>
    public interface IProfileManagerService
    {
        /// <summary>
        /// Loads all device profiles from the default storage location.
        /// </summary>
        /// <returns>A collection of device profiles.</returns>
        Task<IEnumerable<DeviceProfile>> GetAllProfilesAsync();

        /// <summary>
        /// Saves a device profile. If the profile is new, it determines the file path.
        /// </summary>
        /// <param name="profile">The profile to save.</param>
        Task SaveProfileAsync(DeviceProfile profile);

        /// <summary>
        /// Deletes a device profile from the file system.
        /// </summary>
        /// <param name="profile">The profile to delete.</param>
        Task DeleteProfileAsync(DeviceProfile profile);

        /// <summary>
        /// Creates a new, empty device profile instance.
        /// </summary>
        /// <returns>A new device profile.</returns>
        DeviceProfile CreateNewProfile();
    }
}