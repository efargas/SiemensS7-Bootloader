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
        public async Task SaveConfiguration(ViewModels.MainWindowViewModel viewModel, string filePath)
        {
            if (viewModel.PlcConnectionViewModel == null || viewModel.ModbusPowerSupplyViewModel == null || viewModel.FileCompareViewModel == null || viewModel.ConfigurationViewModel == null)
            {
                return;
            }

            var config = new ApplicationConfiguration
            {
                PlcHost = viewModel.PlcConnectionViewModel.PlcHost,
                PlcPort = viewModel.PlcConnectionViewModel.PlcPort,
                ModbusHost = viewModel.ModbusPowerSupplyViewModel.ModbusHost,
                ModbusPort = viewModel.ModbusPowerSupplyViewModel.ModbusPort,
                ModbusCoil = viewModel.ModbusPowerSupplyViewModel.ModbusCoil,
                DelaySeconds = viewModel.ModbusPowerSupplyViewModel.DelaySeconds,
                DumpAddress = viewModel.DumpAddress,
                DumpLength = viewModel.DumpLength,
                CompareFolder = viewModel.FileCompareViewModel.CompareFolder,
                CompareFile1 = viewModel.FileCompareViewModel.CompareFile1,
                CompareFile2 = viewModel.FileCompareViewModel.CompareFile2,
                SelectedSerialPort = viewModel.PlcConnectionViewModel.SelectedSerialPort,
                SocatTcpPort = viewModel.PlcConnectionViewModel.SocatTcpPort,
                SelectedBaudRate = viewModel.PlcConnectionViewModel.SelectedBaudRate,
                SelectedParity = viewModel.PlcConnectionViewModel.SelectedParity,
                SelectedStopBits = viewModel.PlcConnectionViewModel.SelectedStopBits,
                SelectedFlowControl = viewModel.PlcConnectionViewModel.SelectedFlowControl,
                SocatVerbose = viewModel.PlcConnectionViewModel.SocatVerbose,
                SocatHexDump = viewModel.PlcConnectionViewModel.SocatHexDump,
                SocatBlockSize = viewModel.PlcConnectionViewModel.SocatBlockSize,
                PayloadsPath = viewModel.ConfigurationViewModel.PayloadsPath,
                DumpsPath = viewModel.ConfigurationViewModel.DumpsPath,
                LogsPath = viewModel.ConfigurationViewModel.LogsPath,
                ExtractionPath = viewModel.ConfigurationViewModel.ExtractionPath
            };

            var options = new JsonSerializerOptions { WriteIndented = true };
            string json = JsonSerializer.Serialize(config, options);
            await File.WriteAllTextAsync(filePath, json);
        }

        public async Task LoadConfiguration(ViewModels.MainWindowViewModel viewModel, string filePath)
        {
            if (!File.Exists(filePath) || viewModel.PlcConnectionViewModel == null || viewModel.ModbusPowerSupplyViewModel == null || viewModel.FileCompareViewModel == null || viewModel.ConfigurationViewModel == null)
            {
                return;
            }

            string json = await File.ReadAllTextAsync(filePath);
            var config = JsonSerializer.Deserialize<ApplicationConfiguration>(json);

            if (config != null)
            {
                viewModel.PlcConnectionViewModel.PlcHost = config.PlcHost;
                viewModel.PlcConnectionViewModel.PlcPort = config.PlcPort;
                viewModel.ModbusPowerSupplyViewModel.ModbusHost = config.ModbusHost;
                viewModel.ModbusPowerSupplyViewModel.ModbusPort = config.ModbusPort;
                viewModel.ModbusPowerSupplyViewModel.ModbusCoil = config.ModbusCoil;
                viewModel.ModbusPowerSupplyViewModel.DelaySeconds = config.DelaySeconds;
                viewModel.DumpAddress = config.DumpAddress;
                viewModel.DumpLength = config.DumpLength;
                viewModel.FileCompareViewModel.CompareFolder = config.CompareFolder;
                viewModel.FileCompareViewModel.CompareFile1 = config.CompareFile1;
                viewModel.FileCompareViewModel.CompareFile2 = config.CompareFile2;
                viewModel.PlcConnectionViewModel.SelectedSerialPort = config.SelectedSerialPort;
                viewModel.PlcConnectionViewModel.SocatTcpPort = config.SocatTcpPort;
                viewModel.PlcConnectionViewModel.SelectedBaudRate = config.SelectedBaudRate;
                viewModel.PlcConnectionViewModel.SelectedParity = config.SelectedParity;
                viewModel.PlcConnectionViewModel.SelectedStopBits = config.SelectedStopBits;
                viewModel.PlcConnectionViewModel.SelectedFlowControl = config.SelectedFlowControl;
                viewModel.PlcConnectionViewModel.SocatVerbose = config.SocatVerbose;
                viewModel.PlcConnectionViewModel.SocatHexDump = config.SocatHexDump;
                viewModel.PlcConnectionViewModel.SocatBlockSize = config.SocatBlockSize;
                viewModel.ConfigurationViewModel.PayloadsPath = config.PayloadsPath;
                viewModel.ConfigurationViewModel.DumpsPath = config.DumpsPath;
                viewModel.ConfigurationViewModel.LogsPath = config.LogsPath;
                viewModel.ConfigurationViewModel.ExtractionPath = config.ExtractionPath;
            }
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
