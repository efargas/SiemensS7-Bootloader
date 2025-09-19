using S7_Csharp_Utility.Models;
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
        /// <summary>
        /// Saves the application configuration to a file.
        /// </summary>
        /// <param name="config">The configuration to save.</param>
        /// <param name="filePath">The path to the configuration file.</param>
        public async Task SaveConfiguration(ApplicationConfiguration config, string filePath)
        {
            var options = new JsonSerializerOptions { WriteIndented = true };
            string json = JsonSerializer.Serialize(config, options);
            await File.WriteAllTextAsync(filePath, json);
        }

        /// <summary>
        /// Loads the application configuration from a file.
        /// </summary>
        /// <param name="filePath">The path to the configuration file.</param>
        /// <returns>The loaded configuration, or null if the file does not exist.</returns>
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
    }
}
