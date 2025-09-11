using S7_Csharp_Utility.Services;
using System.Windows.Input;
using System.Threading.Tasks;
using System;
using S7.Net;
using System.ComponentModel.DataAnnotations;
using System.Collections.ObjectModel;
using System.Linq;

namespace S7_Csharp_Utility.ViewModels
{
    public class MainWindowViewModel : ViewModelBase
    {
        private string _plcHost = "localhost";
        [Required]
        public string PlcHost
        {
            get => _plcHost;
            set
            {
                _plcHost = value;
                OnPropertyChanged();
            }
        }

        private int _delaySeconds = 1;
        public int DelaySeconds
        {
            get => _delaySeconds;
            set
            {
                _delaySeconds = value;
                OnPropertyChanged();
            }
        }

        private int _plcPort = 102;
        [Range(1, 65535)]
        public int PlcPort
        {
            get => _plcPort;
            set
            {
                _plcPort = value;
                OnPropertyChanged();
            }
        }

        private string _modbusHost = "localhost";
        [Required]
        public string ModbusHost
        {
            get => _modbusHost;
            set
            {
                _modbusHost = value;
                OnPropertyChanged();
            }
        }

        private int _modbusPort = 502;
        [Range(1, 65535)]
        public int ModbusPort
        {
            get => _modbusPort;
            set
            {
                _modbusPort = value;
                OnPropertyChanged();
            }
        }

        private ushort _modbusCoil = 1;
        [Range(1, 65535)]
        public ushort ModbusCoil
        {
            get => _modbusCoil;
            set
            {
                _modbusCoil = value;
                OnPropertyChanged();
            }
        }

        public LoggingService Logging { get; }
        private readonly PowerController _powerController;

        public ICommand PowerOnCommand { get; }
        public ICommand PowerOffCommand { get; }

        private readonly S7.Net.PlcClient _plcClient;
        private readonly S7.Net.PayloadManager _payloadManager;

        private string _dumpAddress = "0x10000000";
        [Required]
        [RegularExpression(@"^0x[0-9a-fA-F]+$", ErrorMessage = "Must be a valid hex address (e.g., 0x10000000)")]
        public string DumpAddress
        {
            get => _dumpAddress;
            set
            {
                _dumpAddress = value;
                OnPropertyChanged();
            }
        }

        private uint _dumpLength = 4096;
        [Range(1, uint.MaxValue)]
        public uint DumpLength
        {
            get => _dumpLength;
            set
            {
                _dumpLength = value;
                OnPropertyChanged();
            }
        }


        private bool _isBusy;
        public bool IsBusy
        {
            get => _isBusy;
            set
            {
                _isBusy = value;
                OnPropertyChanged();
                (UploadStagerCommand as Commands.RelayCommand)?.RaiseCanExecuteChanged();
                (DumpMemoryCommand as Commands.RelayCommand)?.RaiseCanExecuteChanged();
            }
        }

        private bool _stagerInstalled;
        public bool StagerInstalled
        {
            get => _stagerInstalled;
            set
            {
                _stagerInstalled = value;
                OnPropertyChanged();
                (DumpMemoryCommand as Commands.RelayCommand)?.RaiseCanExecuteChanged();
            }
        }

        public ICommand UploadStagerCommand { get; }
        public ICommand DumpMemoryCommand { get; }
        public ICommand BrowseCompareFolderCommand { get; }
        public ICommand BrowseCompareFile1Command { get; }
        public ICommand BrowseCompareFile2Command { get; }
        public ICommand CompareDumpsCommand { get; }
        public ICommand CompareTwoFilesCommand { get; }

        private readonly SocatService _socatService;
        public ObservableCollection<string> AvailableSerialPorts { get; } = new ObservableCollection<string>();
        private string _selectedSerialPort = string.Empty;
        public string SelectedSerialPort
        {
            get => _selectedSerialPort;
            set
            {
                _selectedSerialPort = value;
                OnPropertyChanged();
            }
        }

        private int _socatTcpPort = 8888;
        public int SocatTcpPort
        {
            get => _socatTcpPort;
            set
            {
                _socatTcpPort = value;
                OnPropertyChanged();
            }
        }

        private string _socatStatus = "Stopped";
        public string SocatStatus
        {
            get => _socatStatus;
            set
            {
                _socatStatus = value;
                OnPropertyChanged();
            }
        }

        public ICommand StartSocatCommand { get; }
        public ICommand StopSocatCommand { get; }
        public ICommand RefreshSerialPortsCommand { get; }


        private string _compareFolder = string.Empty;
        public string CompareFolder
        {
            get => _compareFolder;
            set
            {
                _compareFolder = value;
                OnPropertyChanged();
            }
        }

        private string _compareFile1 = string.Empty;
        public string CompareFile1
        {
            get => _compareFile1;
            set
            {
                _compareFile1 = value;
                OnPropertyChanged();
            }
        }

        private string _compareFile2 = string.Empty;
        public string CompareFile2
        {
            get => _compareFile2;
            set
            {
                _compareFile2 = value;
                OnPropertyChanged();
            }
        }

        private readonly Interfaces.IDialogService _dialogService;

        public MainWindowViewModel(LoggingService loggingService, PowerController powerController, S7.Net.PlcClient plcClient, S7.Net.PayloadManager payloadManager, Interfaces.IDialogService dialogService, SocatService socatService)
        {
            Logging = loggingService;
            _powerController = powerController;
            _plcClient = plcClient;
            _payloadManager = payloadManager;
            _dialogService = dialogService;
            _socatService = socatService;

            PowerOnCommand = new Commands.RelayCommand(async _ => await _powerController.SetPowerAsync(ModbusHost, ModbusPort, ModbusCoil, true));
            PowerOffCommand = new Commands.RelayCommand(async _ => await _powerController.SetPowerAsync(ModbusHost, ModbusPort, ModbusCoil, false));
            UploadStagerCommand = new Commands.RelayCommand(async _ => await UploadStager(), _ => !IsBusy);
            DumpMemoryCommand = new Commands.RelayCommand(async _ => await DumpMemory(), _ => !IsBusy && StagerInstalled);

            BrowseCompareFolderCommand = new Commands.RelayCommand(async _ => { var result = await _dialogService.OpenFolderPickerAsync("Select Folder to Compare"); if(result != null) CompareFolder = result; });
            BrowseCompareFile1Command = new Commands.RelayCommand(async _ => { var result = await _dialogService.OpenFilePickerAsync("Select File 1"); if(result != null) CompareFile1 = result; });
            BrowseCompareFile2Command = new Commands.RelayCommand(async _ => { var result = await _dialogService.OpenFilePickerAsync("Select File 2"); if(result != null) CompareFile2 = result; });
            CompareDumpsCommand = new Commands.RelayCommand(async _ => await CompareDumps(), _ => !IsBusy && !string.IsNullOrWhiteSpace(CompareFolder));
            CompareTwoFilesCommand = new Commands.RelayCommand(async _ => await CompareTwoFiles(), _ => !IsBusy && !string.IsNullOrWhiteSpace(CompareFile1) && !string.IsNullOrWhiteSpace(CompareFile2));

            StartSocatCommand = new Commands.RelayCommand(_ => StartSocat(), _ => !IsBusy && !string.IsNullOrWhiteSpace(SelectedSerialPort));
            StopSocatCommand = new Commands.RelayCommand(_ => StopSocat(), _ => _socatService.IsRunning);
            RefreshSerialPortsCommand = new Commands.RelayCommand(_ => RefreshSerialPorts());

            RefreshSerialPorts();
        }

        private async Task UploadStager()
        {
            IsBusy = true;
            try
            {
                await _powerController.SetPowerAsync(ModbusHost, ModbusPort, ModbusCoil, false);
                Logging.Log($"Waiting for {DelaySeconds} seconds before powering on...", LogCategory.Info);
                await Task.Delay(DelaySeconds * 1000);
                await _powerController.SetPowerAsync(ModbusHost, ModbusPort, ModbusCoil, true);

                await Task.Delay(50);

                await RunStagerSequenceAsync();
            }
            catch (Exception ex)
            {
                Logging.Log($"An error occurred during the stager sequence: {ex.Message}", LogCategory.Error);
            }
            finally
            {
                if (_plcClient.IsConnected)
                {
                    _plcClient.Disconnect();
                }
                IsBusy = false;
            }
        }

        private async Task RunStagerSequenceAsync()
        {
            StagerInstalled = false;
            await _plcClient.ConnectAsync(PlcHost, PlcPort);
            if (!_plcClient.IsConnected) return;

            if (await _plcClient.PerformHandshakeAsync())
            {
                await _plcClient.GetVersion();

                byte[] stagerPayload = _payloadManager.GetStagerPayload();
                Logging.Log($"Loaded stager payload ({stagerPayload.Length} bytes).", LogCategory.Info);

                await _plcClient.InstallStager(stagerPayload);
                StagerInstalled = true;
                Logging.Log("Stager is installed and ready.", LogCategory.Info);
            }
        }

        private async Task DumpMemory()
        {
            IsBusy = true;
            try
            {
                if (!uint.TryParse(DumpAddress.Replace("0x", ""), System.Globalization.NumberStyles.HexNumber, System.Globalization.CultureInfo.CurrentCulture, out uint address))
                {
                    Logging.Log("Error: Invalid dump address. Must be a valid hex number (e.g., 0x10000000).", LogCategory.Error);
                    return;
                }
                if (DumpLength == 0)
                {
                    Logging.Log("Error: Invalid dump length. Must be a positive number.", LogCategory.Error);
                    return;
                }

                await RunDumpSequenceAsync(address, DumpLength);
            }
            catch (Exception ex)
            {
                Logging.Log($"An error occurred during the dump sequence: {ex.Message}", LogCategory.Error);
            }
            finally
            {
                IsBusy = false;
            }
        }

        private async Task RunDumpSequenceAsync(uint address, uint length)
        {
            Logging.Log($"Starting memory dump of {length} bytes from 0x{address:X8}...", LogCategory.Info);

            byte[] dumperPayload = _payloadManager.GetMemoryDumperPayload();
            Logging.Log($"Loaded dumper payload ({dumperPayload.Length} bytes).", LogCategory.Info);

            int dumperHookIndex = PlcConstants.DEFAULT_SECOND_ADD_HOOK_IND;
            await _plcClient.InstallAddHookViaStager(PlcConstants.DUMPER_PAYLOAD_LOCATION, dumperPayload, dumperHookIndex);
            Logging.Log("Memory dumper payload installed.", LogCategory.Info);

            var args = new byte[1 + 4 + 4];
            args[0] = (byte)'A';
            BitConverter.GetBytes(address).CopyTo(args, 1);
            BitConverter.GetBytes(length).CopyTo(args, 5);

            await _plcClient.InvokeAddHook(dumperHookIndex, args);
            Logging.Log("Dump command sent. Receiving data...", LogCategory.Info);

            var stopwatch = System.Diagnostics.Stopwatch.StartNew();
            var progress = new Progress<long>(bytesRead =>
            {
                // UI update logic for progress should be here
            });

            var dumpedData = await _plcClient.ReceiveMany(progress);
            stopwatch.Stop();

            string outFilename = $"mem_dump_{address:x8}_{address + length:x8}.bin";
            await System.IO.File.WriteAllBytesAsync(outFilename, dumpedData);
            Logging.Log($"Successfully dumped {dumpedData.Length} bytes to {outFilename} in {stopwatch.Elapsed.TotalSeconds:F1}s.", LogCategory.Info);
        }

        private async Task CompareDumps()
        {
            if (string.IsNullOrWhiteSpace(CompareFolder) || !System.IO.Directory.Exists(CompareFolder))
            {
                await _dialogService.ShowMessageAsync("Error", "Please select a valid folder.");
                return;
            }

            IsBusy = true;
            try
            {
                var comparer = new S7.Utils.DumpComparer(message => Logging.Log(message));
                var fileHashes = await comparer.ComputeFileHashesAsync(CompareFolder);
                string report = comparer.GenerateFolderCompareReport(fileHashes, CompareFolder);

                // The results should be displayed in the UI. This requires more properties in the VM.
                // For now, just showing a popup.
                await _dialogService.ShowMessageAsync("Comparison Result", report);
                Logging.Log("Comparison complete. See popup for detailed result.");
            }
            catch (Exception ex)
            {
                await _dialogService.ShowMessageAsync("Error", $"Error during folder compare: {ex.Message}");
                Logging.Log($"Error during folder compare: {ex.Message}", LogCategory.Error);
            }
            finally
            {
                IsBusy = false;
            }
        }

        private void RefreshSerialPorts()
        {
            AvailableSerialPorts.Clear();
            foreach (var port in System.IO.Ports.SerialPort.GetPortNames())
            {
                AvailableSerialPorts.Add(port);
            }
            if (AvailableSerialPorts.Any())
            {
                SelectedSerialPort = AvailableSerialPorts[0];
            }
        }

        private void StartSocat()
        {
            try
            {
                _socatService.Start(SelectedSerialPort, SocatTcpPort);
                SocatStatus = "Running";
            }
            catch (Exception ex)
            {
                Logging.Log($"Error starting socat: {ex.Message}", LogCategory.Error);
                SocatStatus = "Error";
            }
        }

        private void StopSocat()
        {
            try
            {
                _socatService.Stop();
                SocatStatus = "Stopped";
            }
            catch (Exception ex)
            {
                Logging.Log($"Error stopping socat: {ex.Message}", LogCategory.Error);
                SocatStatus = "Error";
            }
        }

        private async Task CompareTwoFiles()
        {
            if (!System.IO.File.Exists(CompareFile1) || !System.IO.File.Exists(CompareFile2))
            {
                await _dialogService.ShowMessageAsync("Error", "Please select two valid files.");
                return;
            }

            IsBusy = true;
            try
            {
                var comparer = new S7.Utils.DumpComparer();
                string hashA = await comparer.ComputeFileHashAsync(CompareFile1);
                string hashB = await comparer.ComputeFileHashAsync(CompareFile2);
                bool match = hashA == hashB;
                var sb = new System.Text.StringBuilder();
                sb.AppendLine($"File 1: {System.IO.Path.GetFileName(CompareFile1)}");
                sb.AppendLine($"MD5: {hashA}");
                sb.AppendLine($"File 2: {System.IO.Path.GetFileName(CompareFile2)}");
                sb.AppendLine($"MD5: {hashB}");
                sb.AppendLine(match ? "=> MATCH" : "=> DIFFER");

                await _dialogService.ShowMessageAsync("Comparison Result", sb.ToString());
                Logging.Log("Comparison complete. See popup for detailed result.");
            }
            catch (Exception ex)
            {
                await _dialogService.ShowMessageAsync("Error", $"Error during file compare: {ex.Message}");
                Logging.Log($"Error during file compare: {ex.Message}", LogCategory.Error);
            }
            finally
            {
                IsBusy = false;
            }
        }
    }
}
