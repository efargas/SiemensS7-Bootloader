using S7_Csharp_Utility.Models;
using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;

namespace S7_Csharp_Utility.Services
{
    /// <summary>
    /// Service for handling application configuration and device profile management.
    /// Provides methods for saving, loading, and managing configuration files and device profiles.
    /// </summary>
    public sealed class ConfigurationService
    {
        private readonly JsonSerializerOptions _jsonOptions;

        /// <summary>
        /// Initializes a new instance of the <see cref="ConfigurationService"/> class.
        /// </summary>
        public ConfigurationService()
        {
            _jsonOptions = new JsonSerializerOptions
            {
                WriteIndented = true,
                PropertyNamingPolicy = JsonNamingPolicy.CamelCase
            };
        }

        /// <summary>
        /// Saves the application configuration to the specified file path.
        /// </summary>
        /// <param name="config">The application configuration to save.</param>
        /// <param name="filePath">The file path where the configuration should be saved.</param>
        /// <returns>A task representing the asynchronous save operation.</returns>
        /// <exception cref="ArgumentNullException">Thrown when config or filePath is null.</exception>
        /// <exception cref="IOException">Thrown when an I/O error occurs during file operations.</exception>
        public async Task SaveConfigurationAsync(ApplicationConfiguration config, string filePath)
        {
            ArgumentNullException.ThrowIfNull(config);
            ArgumentNullException.ThrowIfNull(filePath);

            try
            {
                var directory = Path.GetDirectoryName(filePath);
                if (!string.IsNullOrEmpty(directory) && !Directory.Exists(directory))
                {
                    Directory.CreateDirectory(directory);
                }

                string json = JsonSerializer.Serialize(config, _jsonOptions);
                await File.WriteAllTextAsync(filePath, json).ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is not ArgumentNullException)
            {
                throw new IOException($"Failed to save configuration to '{filePath}'.", ex);
            }
        }

        /// <summary>
        /// Loads the application configuration from the specified file path.
        /// </summary>
        /// <param name="filePath">The file path from which to load the configuration.</param>
        /// <returns>The loaded application configuration, or null if the file does not exist.</returns>
        /// <exception cref="ArgumentNullException">Thrown when filePath is null.</exception>
        /// <exception cref="IOException">Thrown when an I/O error occurs during file operations.</exception>
        /// <exception cref="JsonException">Thrown when the JSON content is invalid.</exception>
        public async Task<ApplicationConfiguration?> LoadConfigurationAsync(string filePath)
        {
            ArgumentNullException.ThrowIfNull(filePath);

            if (!File.Exists(filePath))
            {
                return null;
            }

            try
            {
                string json = await File.ReadAllTextAsync(filePath).ConfigureAwait(false);
                return JsonSerializer.Deserialize<ApplicationConfiguration>(json, _jsonOptions);
            }
            catch (Exception ex) when (ex is not ArgumentNullException)
            {
                throw new IOException($"Failed to load configuration from '{filePath}'.", ex);
            }
        }

        /// <summary>
        /// Saves a device profile to the specified file path.
        /// </summary>
        /// <param name="profile">The device profile to save.</param>
        /// <param name="filePath">The file path where the profile should be saved.</param>
        /// <returns>A task representing the asynchronous save operation.</returns>
        /// <exception cref="ArgumentNullException">Thrown when profile or filePath is null.</exception>
        /// <exception cref="IOException">Thrown when an I/O error occurs during file operations.</exception>
        public async Task SaveProfileAsync(DeviceProfile profile, string filePath)
        {
            ArgumentNullException.ThrowIfNull(profile);
            ArgumentNullException.ThrowIfNull(filePath);

            try
            {
                var directory = Path.GetDirectoryName(filePath);
                if (!string.IsNullOrEmpty(directory) && !Directory.Exists(directory))
                {
                    Directory.CreateDirectory(directory);
                }

                string json = JsonSerializer.Serialize(profile, _jsonOptions);
                await File.WriteAllTextAsync(filePath, json).ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is not ArgumentNullException)
            {
                throw new IOException($"Failed to save profile to '{filePath}'.", ex);
            }
        }

        /// <summary>
        /// Loads a device profile from the specified file path.
        /// </summary>
        /// <param name="filePath">The file path from which to load the profile.</param>
        /// <returns>The loaded device profile, or null if the file does not exist.</returns>
        /// <exception cref="ArgumentNullException">Thrown when filePath is null.</exception>
        /// <exception cref="IOException">Thrown when an I/O error occurs during file operations.</exception>
        /// <exception cref="JsonException">Thrown when the JSON content is invalid.</exception>
        public async Task<DeviceProfile?> LoadProfileAsync(string filePath)
        {
            ArgumentNullException.ThrowIfNull(filePath);

            if (!File.Exists(filePath))
            {
                return null;
            }

            try
            {
                string json = await File.ReadAllTextAsync(filePath).ConfigureAwait(false);
                return JsonSerializer.Deserialize<DeviceProfile>(json, _jsonOptions);
            }
            catch (Exception ex) when (ex is not ArgumentNullException)
            {
                throw new IOException($"Failed to load profile from '{filePath}'.", ex);
            }
        }

        /// <summary>
        /// Gets the directory path where device profiles are stored.
        /// Creates the directory if it does not exist.
        /// </summary>
        /// <returns>The profiles directory path.</returns>
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

        /// <summary>
        /// Loads all device profiles from the profiles directory.
        /// </summary>
        /// <returns>A list of all loaded device profiles.</returns>
        /// <exception cref="IOException">Thrown when an I/O error occurs during file operations.</exception>
        public async Task<List<DeviceProfile>> LoadAllProfilesAsync()
        {
            var profilesDirectory = GetProfilesDirectory();
            var profiles = new List<DeviceProfile>();

            if (!Directory.Exists(profilesDirectory))
            {
                return profiles;
            }

            try
            {
                var profileFiles = Directory.GetFiles(profilesDirectory, "*.json");

                foreach (var filePath in profileFiles)
                {
                    try
                    {
                        var profile = await LoadProfileAsync(filePath).ConfigureAwait(false);
                        if (profile != null)
                        {
                            profile.FilePath = filePath;
                            profiles.Add(profile);
                        }
                    }
                    catch (Exception ex)
                    {
                        // Log individual profile loading errors but continue with other profiles
                        System.Diagnostics.Debug.WriteLine($"Failed to load profile from '{filePath}': {ex.Message}");
                    }
                }
            }
            catch (Exception ex)
            {
                throw new IOException($"Failed to load profiles from directory '{profilesDirectory}'.", ex);
            }

            return profiles;
        }

        /// <summary>
        /// Deletes a device profile file from the file system.
        /// </summary>
        /// <param name="filePath">The file path of the profile to delete.</param>
        /// <returns>A task representing the asynchronous delete operation.</returns>
        /// <exception cref="ArgumentNullException">Thrown when filePath is null.</exception>
        /// <exception cref="IOException">Thrown when an I/O error occurs during file operations.</exception>
        public Task DeleteProfileAsync(string filePath)
        {
            ArgumentNullException.ThrowIfNull(filePath);

            try
            {
                if (File.Exists(filePath))
                {
                    File.Delete(filePath);
                }
                return Task.CompletedTask;
            }
            catch (Exception ex)
            {
                throw new IOException($"Failed to delete profile at '{filePath}'.", ex);
            }
        }

    }
}
