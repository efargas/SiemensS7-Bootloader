using Microsoft.Extensions.Logging;
using S7_Csharp_Utility.Interfaces;
using S7_Csharp_Utility.Models;
using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Ports;
using System.Text.Json;
using System.Threading.Tasks;

namespace S7_Csharp_Utility.Services
{
    /// <summary>
    /// Service for handling application configuration and device profile management.
    /// Provides methods for saving, loading, and managing configuration files and device profiles.
    /// </summary>
    public sealed class ConfigurationService : IConfigurationService
    {
        private readonly ILogger<ConfigurationService> _logger;
        private readonly JsonSerializerOptions _jsonOptions;

        /// <summary>
        /// Initializes a new instance of the <see cref="ConfigurationService"/> class.
        /// </summary>
        public ConfigurationService(ILogger<ConfigurationService> logger)
        {
            _logger = logger;
            _jsonOptions = new JsonSerializerOptions
            {
                WriteIndented = true,
                PropertyNamingPolicy = JsonNamingPolicy.CamelCase
            };
        }

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
                _logger.LogError(ex, "Failed to save configuration to {FilePath}", filePath);
                throw new IOException($"Failed to save configuration to '{filePath}'.", ex);
            }
        }

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
                _logger.LogError(ex, "Failed to load configuration from {FilePath}", filePath);
                throw new IOException($"Failed to load configuration from '{filePath}'.", ex);
            }
        }

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
                _logger.LogError(ex, "Failed to save profile to {FilePath}", filePath);
                throw new IOException($"Failed to save profile to '{filePath}'.", ex);
            }
        }

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
                _logger.LogError(ex, "Failed to load profile from {FilePath}", filePath);
                throw new IOException($"Failed to load profile from '{filePath}'.", ex);
            }
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
                        _logger.LogWarning(ex, "Failed to load profile from {FilePath}, skipping.", filePath);
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to load profiles from directory {Directory}", profilesDirectory);
                throw new IOException($"Failed to load profiles from directory '{profilesDirectory}'.", ex);
            }

            return profiles;
        }

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
                _logger.LogError(ex, "Failed to delete profile at {FilePath}", filePath);
                throw new IOException($"Failed to delete profile at '{filePath}'.", ex);
            }
        }

        public string GetPayloadsPath() => Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "Resources", "payloads"));
        public string GetDefaultDumpsPath() => Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "Resources", "dumps"));
        public string GetDefaultLogsPath() => Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "Resources", "logs"));
        public string GetDefaultExtractionPath() => Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "Resources", "extracted"));

        public string ResolvePath(string configuredPath, string defaultPath)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(configuredPath))
                {
                    configuredPath = defaultPath;
                }

                string absolutePath = Path.IsPathRooted(configuredPath)
                    ? Path.GetFullPath(configuredPath)
                    : Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, configuredPath));

                if (!Directory.Exists(absolutePath))
                {
                    Directory.CreateDirectory(absolutePath);
                }

                return absolutePath;
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to resolve path {ConfiguredPath}. Falling back to default {DefaultPath}", configuredPath, defaultPath);
                var fallbackPath = Path.GetFullPath(defaultPath);
                if (!Directory.Exists(fallbackPath))
                {
                    Directory.CreateDirectory(fallbackPath);
                }
                return fallbackPath;
            }
        }

        public ApplicationConfiguration CreateDefault()
        {
            return new ApplicationConfiguration
            {
                PlcHost = "localhost",
                PlcPort = 102,
                ModbusHost = "localhost",
                ModbusPort = 502,
                ModbusCoil = 1,
                DelaySeconds = 1,
                DumpAddress = "0x691E28",
                DumpLength = 16,
                CompareFolder = string.Empty,
                CompareFile1 = string.Empty,
                CompareFile2 = string.Empty,
                SelectedSerialPort = "/dev/ttyUSB0",
                SocatTcpPort = 1238,
                SelectedBaudRate = 38400,
                SelectedParity = Parity.Even,
                SelectedStopBits = StopBits.One,
                SelectedFlowControl = Handshake.None,
                SocatVerbose = true,
                SocatHexDump = true,
                SocatBlockSize = 4,
                PayloadsPath = GetPayloadsPath(),
                DumpsPath = GetDefaultDumpsPath(),
                LogsPath = GetDefaultLogsPath(),
                ExtractionPath = GetDefaultExtractionPath()
            };
        }
    }
}