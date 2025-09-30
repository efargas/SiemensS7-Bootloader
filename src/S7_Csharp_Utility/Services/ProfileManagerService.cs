using S7_Csharp_Utility.Interfaces;
using S7_Csharp_Utility.Models;
using System;
using System.Collections.Generic;
using System.IO;
using System.Threading.Tasks;

namespace S7_Csharp_Utility.Services
{
    /// <summary>
    /// A service for managing device profiles.
    /// </summary>
    public class ProfileManagerService : IProfileManagerService
    {
        private readonly ConfigurationService _configService;

        public ProfileManagerService(ConfigurationService configService)
        {
            _configService = configService ?? throw new ArgumentNullException(nameof(configService));
        }

        /// <inheritdoc />
        public Task<IEnumerable<DeviceProfile>> GetAllProfilesAsync()
        {
            return _configService.LoadAllProfilesAsync();
        }

        /// <inheritdoc />
        public Task SaveProfileAsync(DeviceProfile profile)
        {
            if (profile == null) throw new ArgumentNullException(nameof(profile));

            if (string.IsNullOrEmpty(profile.FilePath))
            {
                var profilesDir = _configService.GetProfilesDirectory();
                // Sanitize ModelName to create a valid file name
                var fileName = string.Join("_", profile.ModelName.Split(Path.GetInvalidFileNameChars()));
                profile.FilePath = Path.Combine(profilesDir, $"{fileName}.json");
            }

            return _configService.SaveProfileAsync(profile, profile.FilePath);
        }

        /// <inheritdoc />
        public Task DeleteProfileAsync(DeviceProfile profile)
        {
            if (profile == null) throw new ArgumentNullException(nameof(profile));

            if (!string.IsNullOrEmpty(profile.FilePath))
            {
                return _configService.DeleteProfileAsync(profile.FilePath);
            }
            return Task.CompletedTask;
        }

        /// <inheritdoc />
        public DeviceProfile CreateNewProfile()
        {
            return new DeviceProfile { ModelName = "New Profile" };
        }
    }
}