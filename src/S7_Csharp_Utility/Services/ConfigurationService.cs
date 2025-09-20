using S7_Csharp_Utility.Models;
using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;
using System.Threading.Tasks;

namespace S7_Csharp_Utility.Services
{
    /// <summary>
    /// Service for handling application configuration.
    /// </summary>
    public class ConfigurationService
    {
        public async Task SaveConfiguration(ApplicationConfiguration config, string filePath)
        {
            var options = new JsonSerializerOptions { WriteIndented = true };
            string json = JsonSerializer.Serialize(config, options);
            await File.WriteAllTextAsync(filePath, json);
        }

        public async Task<ApplicationConfiguration?> LoadConfiguration(string filePath)
        {
            if (!File.Exists(filePath))
            {
                return null;
            }

            string json = await File.ReadAllTextAsync(filePath);
            return JsonSerializer.Deserialize<ApplicationConfiguration>(json);
        }

        public async Task SaveProfileAsync(DeviceProfile profile, string filePath)
        {
            var options = new JsonSerializerOptions { WriteIndented = true };
            string json = JsonSerializer.Serialize(profile, options);
            await File.WriteAllTextAsync(filePath, json);
        }

        public async Task<DeviceProfile?> LoadProfileAsync(string filePath)
        {
            if (!File.Exists(filePath))
            {
                return null;
            }

            string json = await File.ReadAllTextAsync(filePath);
            return JsonSerializer.Deserialize<DeviceProfile>(json);
        }

        public string GetProfilesDirectory()
        {
            string baseDirectory = AppContext.BaseDirectory;
            string profilesPath = Path.Combine(baseDirectory, "Profiles");
            if (!Directory.Exists(profilesPath))
            {
                Directory.CreateDirectory(profilesPath);
            }
            return profilesPath;
        }

        public async Task<List<DeviceProfile>> LoadAllProfilesAsync()
        {
            var profilesDirectory = GetProfilesDirectory();
            var profiles = new List<DeviceProfile>();
            if (!Directory.Exists(profilesDirectory))
            {
                return profiles;
            }

            var profileFiles = Directory.GetFiles(profilesDirectory, "*.json");
            foreach (var filePath in profileFiles)
            {
                var profile = await LoadProfileAsync(filePath);
                if (profile != null)
                {
                    profile.FilePath = filePath;
                    profiles.Add(profile);
                }
            }
            return profiles;
        }

        public Task DeleteProfileAsync(string filePath)
        {
            if (File.Exists(filePath))
            {
                File.Delete(filePath);
            }
            return Task.CompletedTask;
        }
    }
}
