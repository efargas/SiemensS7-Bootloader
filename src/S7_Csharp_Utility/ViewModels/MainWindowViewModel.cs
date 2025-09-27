#nullable enable
using S7_Csharp_Utility.Services;
using S7_Csharp_Utility.Commands;
using S7_Csharp_Utility.Extensions;
using S7_Csharp_Utility.ViewModels.Features;
using System.Windows.Input;
using System.Threading.Tasks;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using S7_Csharp_Utility.Models;
using S7_Csharp_Utility.Interfaces;
using S7.Core.Abstractions.Services;
using Microsoft.Extensions.Logging;

namespace S7_Csharp_Utility.ViewModels
{
    /// <summary>
    /// The main view model for the application.
    /// </summary>
    public class MainWindowViewModel : ViewModelBase
    {
        private readonly IApplicationStateService _state;
        private readonly IViewService _viewService;
        private readonly IPlcOperationService _plcOperationService;
        private readonly ILogger<MainWindowViewModel> _logger;
        private readonly IDialogService _dialogService;

        /// <summary>
        /// Initializes a new instance of the MainWindowViewModel class.
        /// </summary>
        public MainWindowViewModel(
            IApplicationStateService applicationStateService,
            IPayloadDiscoveryService payloadDiscoveryService,
            LoggingService loggingService,
            SocatLoggerService socatLoggerService,
            IViewService viewService,
            PlcConnectionViewModel plcConnectionViewModel,
            ModbusPowerSupplyViewModel modbusPowerSupplyViewModel,
            ConfigurationViewModel configurationViewModel,
            FileCompareViewModel fileCompareViewModel,
            MemoryDumpFeatureViewModel memoryDumpFeatureViewModel,
            ExploitSequenceFeatureViewModel exploitSequenceFeatureViewModel,
            IPlcOperationService plcOperationService,
            ILogger<MainWindowViewModel> logger,
            IDialogService dialogService)
        {
            // Initialize services
            _state = applicationStateService ?? throw new ArgumentNullException(nameof(applicationStateService));
            _viewService = viewService ?? throw new ArgumentNullException(nameof(viewService));
            _plcOperationService = plcOperationService ?? throw new ArgumentNullException(nameof(plcOperationService));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
            _dialogService = dialogService ?? throw new ArgumentNullException(nameof(dialogService));
            PayloadDiscoveryService = payloadDiscoveryService ?? throw new ArgumentNullException(nameof(payloadDiscoveryService));

            // Initialize properties
            PlcConnectionViewModel = plcConnectionViewModel;
            ModbusPowerSupplyViewModel = modbusPowerSupplyViewModel;
            ConfigurationViewModel = configurationViewModel;
            FileCompareViewModel = fileCompareViewModel;
            MemoryDumpFeature = memoryDumpFeatureViewModel;
            ExploitSequenceFeature = exploitSequenceFeatureViewModel;
            Logging = loggingService;
            SocatLogging = socatLoggerService;

            // Initialize commands and start services
            InitializeCommands();
        }

        public PlcConnectionViewModel? PlcConnectionViewModel { get; private set; }
        public ModbusPowerSupplyViewModel? ModbusPowerSupplyViewModel { get; private set; }
        public ConfigurationViewModel ConfigurationViewModel { get; private set; }
        public FileCompareViewModel FileCompareViewModel { get; private set; }
        public MemoryDumpFeatureViewModel MemoryDumpFeature { get; private set; }
        public ExploitSequenceFeatureViewModel ExploitSequenceFeature { get; private set; }
        public LoggingService Logging { get; private set; }
        public SocatLoggerService SocatLogging { get; private set; }
        public IPayloadDiscoveryService PayloadDiscoveryService { get; }

        private bool _isComparing;
        public bool IsComparing
        {
            get => _isComparing;
            set => SetProperty(ref _isComparing, value);
        }

        private string _validationSummary = string.Empty;
        public string ValidationSummary
        {
            get => _validationSummary;
            set => SetProperty(ref _validationSummary, value);
        }

        private bool _hasValidationErrors;
        public bool HasValidationErrors
        {
            get => _hasValidationErrors;
            set => SetProperty(ref _hasValidationErrors, value);
        }

        public ICommand LoadProfileCommand { get; private set; } = null!;
        public ICommand ShowProfileManagementCommand { get; private set; } = null!;
        public ICommand ShowFirmwareUnpackerCommand { get; private set; } = null!;
        public ICommand SaveConfigurationCommand { get; private set; } = null!;
        public ICommand LoadConfigurationCommand { get; private set; } = null!;
        public ICommand ExitCommand { get; private set; } = null!;
        public ICommand CancelScanCommand { get; private set; } = null!;

        public ObservableCollection<MemoryRegion> MemoryRegions => _state.LoadedProfile?.Regions ?? new ObservableCollection<MemoryRegion>();

        private MemoryRegion? _selectedMemoryRegion;
        public MemoryRegion? SelectedMemoryRegion
        {
            get => _selectedMemoryRegion;
            set
            {
                _selectedMemoryRegion = value;
                OnPropertyChanged();
                if (_selectedMemoryRegion != null)
                {
                    MemoryDumpFeature.DumpAddress = _selectedMemoryRegion.Address;
                    MemoryDumpFeature.DumpLength = _selectedMemoryRegion.Size;
                }
            }
        }

        private void InitializeCommands()
        {
            // Initialize commands
            LoadProfileCommand = new AsyncRelayCommand(async _ => await _state.LoadProfileAsync().ConfigureAwait(false), _ => true);
            ShowProfileManagementCommand = new RelayCommand(_ => ShowProfileManagement(), _ => true);
            ShowFirmwareUnpackerCommand = new RelayCommand(_ => ShowFirmwareUnpacker(), _ => true);
            SaveConfigurationCommand = new AsyncRelayCommand(async _ => await _state.SaveConfigurationAsync().ConfigureAwait(false), _ => true);
            LoadConfigurationCommand = new AsyncRelayCommand(async _ => await _state.LoadConfigurationAsync().ConfigureAwait(false), _ => true);
            ExitCommand = new RelayCommand(_ => _viewService.Exit(), _ => true);
            CancelScanCommand = new RelayCommand(_ => PayloadDiscoveryService.CancelScan(), _ => PayloadDiscoveryService.IsScanning);

            // Subscribe to service events
            _plcOperationService.ConnectionStatusChanged += OnPlcConnectionStatusChanged;
            _plcOperationService.OperationCompleted += OnPlcOperationCompleted;
            _state.PropertyChanged += (s, e) =>
            {
                if (e.PropertyName == nameof(IApplicationStateService.LoadedProfile))
                {
                    OnPropertyChanged(nameof(MemoryRegions));
                }
            };

            PayloadDiscoveryService.ScanPayloadsAsync().FireAndForget(ex => HandleException(ex));
        }

        private void HandleException(Exception ex)
        {
            _logger.LogError(ex, "An unexpected error occurred in MainWindowViewModel");
            Logging.Log($"An unexpected error occurred: {ex.ToString()}", LogCategory.Error);
            _dialogService.ShowMessageAsync("Unexpected Error", $"An unexpected error occurred: {ex.Message}");
        }

        private void OnPlcConnectionStatusChanged(object? sender, PlcConnectionStatusChangedEventArgs e)
        {
            _logger.LogInformation("PLC connection status changed from {PreviousStatus} to {CurrentStatus}",
                e.PreviousStatus, e.CurrentStatus);
        }

        private void OnPlcOperationCompleted(object? sender, PlcOperationCompletedEventArgs e)
        {
            _logger.LogInformation("PLC operation '{OperationName}' completed. Success: {IsSuccess}, Duration: {Duration}ms",
                e.OperationName, e.IsSuccess, e.Duration.TotalMilliseconds);

            if (!e.IsSuccess && !string.IsNullOrEmpty(e.ErrorMessage))
            {
                Logging.Log($"PLC operation '{e.OperationName}' failed: {e.ErrorMessage}", LogCategory.Error);
            }
        }

        private void ShowProfileManagement()
        {
            _viewService.ShowProfileManagementWindow(profile =>
            {
                if (profile != null)
                {
                    _state.LoadedProfile = profile;
                }
            });
        }

        private void ShowFirmwareUnpacker()
        {
            if (_state.ExtractionPath != null)
            {
                _viewService.ShowFirmwareUnpackerWindow(_state.ExtractionPath);
            }
        }

        protected override void OnValidationChanged()
        {
            base.OnValidationChanged();
            var allErrors = new List<string>();
            HasValidationErrors = allErrors.Any();
            ValidationSummary = HasValidationErrors
                ? $"⚠️ {allErrors.Count} validation error(s): {string.Join("; ", allErrors)}"
                : string.Empty;
        }
    }
}
