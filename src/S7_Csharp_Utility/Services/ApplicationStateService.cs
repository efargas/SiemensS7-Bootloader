using Microsoft.Extensions.Logging;
using S7_Csharp_Utility.Interfaces;
using S7_Csharp_Utility.Models;
using System;
using System.IO;
using System.Threading.Tasks;

namespace S7_Csharp_Utility.Services
{
    /// <summary>
    /// A service for managing the application's overall state by handling configuration and profile persistence.
    /// </summary>
    public class ApplicationStateService : IApplicationStateService
    {
        private const string ConfigFileName = "config.json";

        private readonly ILogger<ApplicationStateService> _logger;
        private readonly ConfigurationService _configService;

        public ApplicationStateService(
            ILogger<ApplicationStateService> logger,
            ConfigurationService configService)
        {
            _logger = logger;
            _configService = configService;
        }

        /// <inheritdoc />
        public async Task<ApplicationConfiguration?> LoadStateFromDefaultLocationAsync()
        {
            try
            {
                var path = Path.Combine(AppContext.BaseDirectory, ConfigFileName);
                if (!File.Exists(path))
                {
                    _logger.LogInformation("Configuration file not found at {Path}. A default configuration will be created on exit.", path);
                    return null;
                }

                return await _configService.LoadConfigurationAsync(path);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Could not load configuration.");
                return null;
            }
        }

        /// <inheritdoc />
        public async Task SaveStateToDefaultLocationAsync(ApplicationConfiguration config)
        {
            try
            {
                var path = Path.Combine(AppContext.BaseDirectory, ConfigFileName);
                await _configService.SaveConfigurationAsync(config, path);
                _logger.LogInformation("Application configuration saved to {Path}.", path);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Could not save configuration.");
            }
        }

        /// <inheritdoc />
        public async Task<DeviceProfile?> LoadProfileAsync(string path)
        {
            try
            {
                return await _configService.LoadProfileAsync(path);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to load profile from {Path}", path);
                return null;
            }
        }
    }
}