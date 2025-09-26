using System;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Threading;
using System.Threading.Tasks;
using Avalonia.Threading;
using Microsoft.Extensions.Logging;
using Moq;
using S7.Core.Abstractions.Services;
using S7.Net;
using S7.Utils;
using S7_Csharp_Utility.Interfaces;
using S7_Csharp_Utility.Services;
using S7_Csharp_Utility.ViewModels;
using Xunit;

namespace S7_Csharp_Utility.Tests.ViewModels
{
    /// <summary>
    /// Unit tests for MainWindowViewModel focusing on UI state management and property changes.
    /// Business logic testing is handled by service layer tests.
    /// </summary>
    public class MainWindowViewModelTests : IDisposable
    {
        private readonly Mock<ILogger<MainWindowViewModel>> _mockLogger;
        private readonly Mock<IPlcOperationService> _mockPlcOperationService;
        private readonly Mock<IMemoryDumpService> _mockMemoryDumpService;
        private readonly Mock<IStagerService> _mockStagerService;
        private readonly Mock<IPayloadService> _mockPayloadService;
        private readonly Mock<ICommunicationChannelService> _mockCommunicationChannelService;
        private readonly Mock<IPowerSupplyService> _mockPowerSupplyService;
        private readonly Mock<IConfigurationValidationService> _mockConfigurationValidationService;
        private readonly Mock<LoggingService> _mockLoggingService;
        private readonly Mock<SocatLoggerService> _mockSocatLoggerService;
        private readonly Mock<ConfigurationService> _mockConfigurationService;
        private readonly Mock<PayloadManager> _mockPayloadManager;
        private readonly Mock<SocatService> _mockSocatService;
        private readonly Mock<IDialogService> _mockDialogService;
        private readonly Mock<IViewService> _mockViewService;
        private readonly MainWindowViewModel _viewModel;

        public MainWindowViewModelTests()
        {
            // Setup all mock dependencies
            _mockLogger = new Mock<ILogger<MainWindowViewModel>>();
            _mockPlcOperationService = new Mock<IPlcOperationService>();
            _mockMemoryDumpService = new Mock<IMemoryDumpService>();
            _mockStagerService = new Mock<IStagerService>();
            _mockPayloadService = new Mock<IPayloadService>();
            _mockCommunicationChannelService = new Mock<ICommunicationChannelService>();
            _mockPowerSupplyService = new Mock<IPowerSupplyService>();
            _mockConfigurationValidationService = new Mock<IConfigurationValidationService>();
            _mockLoggingService = new Mock<LoggingService>(Mock.Of<Dispatcher>(), Mock.Of<ResourceManagerService>());
            _mockSocatLoggerService = new Mock<SocatLoggerService>(Mock.Of<Dispatcher>());
            _mockConfigurationService = new Mock<ConfigurationService>();
            _mockPayloadManager = new Mock<PayloadManager>(AppContext.BaseDirectory);
            _mockSocatService = new Mock<SocatService>();
            _mockDialogService = new Mock<IDialogService>();
            _mockViewService = new Mock<IViewService>();

            // Create the ViewModel with all dependencies
            _viewModel = new MainWindowViewModel(
                _mockLogger.Object,
                _mockPlcOperationService.Object,
                _mockMemoryDumpService.Object,
                _mockStagerService.Object,
                _mockPayloadService.Object,
                _mockCommunicationChannelService.Object,
                _mockPowerSupplyService.Object,
                _mockConfigurationValidationService.Object,
                _mockLoggingService.Object,
                _mockSocatLoggerService.Object,
                _mockConfigurationService.Object,
                _mockPayloadManager.Object,
                _mockSocatService.Object,
                _mockDialogService.Object,
                _mockViewService.Object
            );
        }

        public void Dispose()
        {
            _viewModel?.Dispose();
        }

        [Fact]
        public void Constructor_WithValidDependencies_InitializesProperties()
        {
            // Assert
            Assert.NotNull(_viewModel.DiscoveredPayloads);
            Assert.Empty(_viewModel.DiscoveredPayloads);
            Assert.NotNull(_viewModel.DumpMemoryCommand);
            Assert.NotNull(_viewModel.InstallStagerCommand);
            Assert.NotNull(_viewModel.ScanPayloadsCommand);
            Assert.NotNull(_viewModel.ConnectCommand);
            Assert.NotNull(_viewModel.DisconnectCommand);
        }

        [Fact]
        public void Constructor_WithNullLogger_ThrowsArgumentNullException()
        {
            // Act & Assert
            Assert.Throws<ArgumentNullException>(() => new MainWindowViewModel(
                null!,
                _mockPlcOperationService.Object,
                _mockMemoryDumpService.Object,
                _mockStagerService.Object,
                _mockPayloadService.Object,
                _mockCommunicationChannelService.Object,
                _mockPowerSupplyService.Object,
                _mockConfigurationValidationService.Object,
                _mockLoggingService.Object,
                _mockSocatLoggerService.Object,
                _mockConfigurationService.Object,
                _mockPayloadManager.Object,
                _mockSocatService.Object,
                _mockDialogService.Object,
                _mockViewService.Object
            ));
        }

        [Fact]
        public void IsConnected_InitialValue_IsFalse()
        {
            // Assert
            Assert.False(_viewModel.IsConnected);
        }

        [Fact]
        public void IsConnected_PropertyChanged_RaisesPropertyChangedEvent()
        {
            // Arrange
            var propertyChangedRaised = false;
            _viewModel.PropertyChanged += (sender, e) =>
            {
                if (e.PropertyName == nameof(MainWindowViewModel.IsConnected))
                    propertyChangedRaised = true;
            };

            // Act
            _viewModel.IsConnected = true;

            // Assert
            Assert.True(propertyChangedRaised);
            Assert.True(_viewModel.IsConnected);
        }

        [Fact]
        public void IsBusy_InitialValue_IsFalse()
        {
            // Assert
            Assert.False(_viewModel.IsBusy);
        }

        [Fact]
        public void IsBusy_PropertyChanged_RaisesPropertyChangedEvent()
        {
            // Arrange
            var propertyChangedRaised = false;
            _viewModel.PropertyChanged += (sender, e) =>
            {
                if (e.PropertyName == nameof(MainWindowViewModel.IsBusy))
                    propertyChangedRaised = true;
            };

            // Act
            _viewModel.IsBusy = true;

            // Assert
            Assert.True(propertyChangedRaised);
            Assert.True(_viewModel.IsBusy);
        }

        [Fact]
        public void StatusMessage_InitialValue_IsEmpty()
        {
            // Assert
            Assert.Equal(string.Empty, _viewModel.StatusMessage);
        }

        [Fact]
        public void StatusMessage_PropertyChanged_RaisesPropertyChangedEvent()
        {
            // Arrange
            var propertyChangedRaised = false;
            var newMessage = "Test status message";
            _viewModel.PropertyChanged += (sender, e) =>
            {
                if (e.PropertyName == nameof(MainWindowViewModel.StatusMessage))
                    propertyChangedRaised = true;
            };

            // Act
            _viewModel.StatusMessage = newMessage;

            // Assert
            Assert.True(propertyChangedRaised);
            Assert.Equal(newMessage, _viewModel.StatusMessage);
        }

        [Fact]
        public void SelectedPayload_InitialValue_IsNull()
        {
            // Assert
            Assert.Null(_viewModel.SelectedPayload);
        }

        [Fact]
        public void SelectedPayload_PropertyChanged_RaisesPropertyChangedEvent()
        {
            // Arrange
            var propertyChangedRaised = false;
            var payload = new PayloadInfo { Name = "test.bin", Path = "/test/test.bin" };
            _viewModel.PropertyChanged += (sender, e) =>
            {
                if (e.PropertyName == nameof(MainWindowViewModel.SelectedPayload))
                    propertyChangedRaised = true;
            };

            // Act
            _viewModel.SelectedPayload = payload;

            // Assert
            Assert.True(propertyChangedRaised);
            Assert.Equal(payload, _viewModel.SelectedPayload);
        }

        [Fact]
        public void MemoryAddress_InitialValue_IsZero()
        {
            // Assert
            Assert.Equal(0u, _viewModel.MemoryAddress);
        }

        [Fact]
        public void MemoryAddress_PropertyChanged_RaisesPropertyChangedEvent()
        {
            // Arrange
            var propertyChangedRaised = false;
            var newAddress = 0x1000u;
            _viewModel.PropertyChanged += (sender, e) =>
            {
                if (e.PropertyName == nameof(MainWindowViewModel.MemoryAddress))
                    propertyChangedRaised = true;
            };

            // Act
            _viewModel.MemoryAddress = newAddress;

            // Assert
            Assert.True(propertyChangedRaised);
            Assert.Equal(newAddress, _viewModel.MemoryAddress);
        }

        [Fact]
        public void MemoryLength_InitialValue_IsZero()
        {
            // Assert
            Assert.Equal(0u, _viewModel.MemoryLength);
        }

        [Fact]
        public void MemoryLength_PropertyChanged_RaisesPropertyChangedEvent()
        {
            // Arrange
            var propertyChangedRaised = false;
            var newLength = 1024u;
            _viewModel.PropertyChanged += (sender, e) =>
            {
                if (e.PropertyName == nameof(MainWindowViewModel.MemoryLength))
                    propertyChangedRaised = true;
            };

            // Act
            _viewModel.MemoryLength = newLength;

            // Assert
            Assert.True(propertyChangedRaised);
            Assert.Equal(newLength, _viewModel.MemoryLength);
        }

        [Fact]
        public void DiscoveredPayloads_InitialValue_IsEmptyObservableCollection()
        {
            // Assert
            Assert.NotNull(_viewModel.DiscoveredPayloads);
            Assert.IsType<ObservableCollection<PayloadInfo>>(_viewModel.DiscoveredPayloads);
            Assert.Empty(_viewModel.DiscoveredPayloads);
        }

        [Fact]
        public void DiscoveredPayloads_AddItem_RaisesCollectionChangedEvent()
        {
            // Arrange
            var collectionChangedRaised = false;
            var payload = new PayloadInfo { Name = "test.bin", Path = "/test/test.bin" };
            _viewModel.DiscoveredPayloads.CollectionChanged += (sender, e) =>
            {
                collectionChangedRaised = true;
            };

            // Act
            _viewModel.DiscoveredPayloads.Add(payload);

            // Assert
            Assert.True(collectionChangedRaised);
            Assert.Single(_viewModel.DiscoveredPayloads);
            Assert.Equal(payload, _viewModel.DiscoveredPayloads[0]);
        }

        [Fact]
        public void Commands_InitialState_AreNotNull()
        {
            // Assert
            Assert.NotNull(_viewModel.DumpMemoryCommand);
            Assert.NotNull(_viewModel.InstallStagerCommand);
            Assert.NotNull(_viewModel.ScanPayloadsCommand);
            Assert.NotNull(_viewModel.ConnectCommand);
            Assert.NotNull(_viewModel.DisconnectCommand);
        }

        [Fact]
        public void DumpMemoryCommand_WhenNotConnected_CannotExecute()
        {
            // Arrange
            _viewModel.IsConnected = false;

            // Act
            var canExecute = _viewModel.DumpMemoryCommand.CanExecute(null);

            // Assert
            Assert.False(canExecute);
        }

        [Fact]
        public void DumpMemoryCommand_WhenConnectedAndNotBusy_CanExecute()
        {
            // Arrange
            _viewModel.IsConnected = true;
            _viewModel.IsBusy = false;

            // Act
            var canExecute = _viewModel.DumpMemoryCommand.CanExecute(null);

            // Assert
            Assert.True(canExecute);
        }

        [Fact]
        public void DumpMemoryCommand_WhenBusy_CannotExecute()
        {
            // Arrange
            _viewModel.IsConnected = true;
            _viewModel.IsBusy = true;

            // Act
            var canExecute = _viewModel.DumpMemoryCommand.CanExecute(null);

            // Assert
            Assert.False(canExecute);
        }

        [Fact]
        public void InstallStagerCommand_WhenNotConnected_CannotExecute()
        {
            // Arrange
            _viewModel.IsConnected = false;
            _viewModel.SelectedPayload = new PayloadInfo { Name = "test.bin" };

            // Act
            var canExecute = _viewModel.InstallStagerCommand.CanExecute(null);

            // Assert
            Assert.False(canExecute);
        }

        [Fact]
        public void InstallStagerCommand_WhenNoPayloadSelected_CannotExecute()
        {
            // Arrange
            _viewModel.IsConnected = true;
            _viewModel.SelectedPayload = null;

            // Act
            var canExecute = _viewModel.InstallStagerCommand.CanExecute(null);

            // Assert
            Assert.False(canExecute);
        }

        [Fact]
        public void InstallStagerCommand_WhenConnectedAndPayloadSelected_CanExecute()
        {
            // Arrange
            _viewModel.IsConnected = true;
            _viewModel.IsBusy = false;
            _viewModel.SelectedPayload = new PayloadInfo { Name = "test.bin" };

            // Act
            var canExecute = _viewModel.InstallStagerCommand.CanExecute(null);

            // Assert
            Assert.True(canExecute);
        }

        [Fact]
        public void ScanPayloadsCommand_WhenNotBusy_CanExecute()
        {
            // Arrange
            _viewModel.IsBusy = false;

            // Act
            var canExecute = _viewModel.ScanPayloadsCommand.CanExecute(null);

            // Assert
            Assert.True(canExecute);
        }

        [Fact]
        public void ScanPayloadsCommand_WhenBusy_CannotExecute()
        {
            // Arrange
            _viewModel.IsBusy = true;

            // Act
            var canExecute = _viewModel.ScanPayloadsCommand.CanExecute(null);

            // Assert
            Assert.False(canExecute);
        }

        [Fact]
        public void ConnectCommand_WhenNotConnectedAndNotBusy_CanExecute()
        {
            // Arrange
            _viewModel.IsConnected = false;
            _viewModel.IsBusy = false;

            // Act
            var canExecute = _viewModel.ConnectCommand.CanExecute(null);

            // Assert
            Assert.True(canExecute);
        }

        [Fact]
        public void ConnectCommand_WhenAlreadyConnected_CannotExecute()
        {
            // Arrange
            _viewModel.IsConnected = true;

            // Act
            var canExecute = _viewModel.ConnectCommand.CanExecute(null);

            // Assert
            Assert.False(canExecute);
        }

        [Fact]
        public void DisconnectCommand_WhenConnected_CanExecute()
        {
            // Arrange
            _viewModel.IsConnected = true;
            _viewModel.IsBusy = false;

            // Act
            var canExecute = _viewModel.DisconnectCommand.CanExecute(null);

            // Assert
            Assert.True(canExecute);
        }

        [Fact]
        public void DisconnectCommand_WhenNotConnected_CannotExecute()
        {
            // Arrange
            _viewModel.IsConnected = false;

            // Act
            var canExecute = _viewModel.DisconnectCommand.CanExecute(null);

            // Assert
            Assert.False(canExecute);
        }

        [Fact]
        public void PropertyChanged_MultipleProperties_RaisesEventsForEachProperty()
        {
            // Arrange
            var propertyChangedEvents = new List<string>();
            _viewModel.PropertyChanged += (sender, e) =>
            {
                if (e.PropertyName != null)
                    propertyChangedEvents.Add(e.PropertyName);
            };

            // Act
            _viewModel.IsConnected = true;
            _viewModel.IsBusy = true;
            _viewModel.StatusMessage = "Test message";
            _viewModel.MemoryAddress = 0x1000;

            // Assert
            Assert.Contains(nameof(MainWindowViewModel.IsConnected), propertyChangedEvents);
            Assert.Contains(nameof(MainWindowViewModel.IsBusy), propertyChangedEvents);
            Assert.Contains(nameof(MainWindowViewModel.StatusMessage), propertyChangedEvents);
            Assert.Contains(nameof(MainWindowViewModel.MemoryAddress), propertyChangedEvents);
        }

        [Fact]
        public void ViewModel_ImplementsINotifyPropertyChanged()
        {
            // Assert
            Assert.IsAssignableFrom<INotifyPropertyChanged>(_viewModel);
        }

        [Fact]
        public void ViewModel_ImplementsIDisposable()
        {
            // Assert
            Assert.IsAssignableFrom<IDisposable>(_viewModel);
        }

        [Fact]
        public void Dispose_DoesNotThrow()
        {
            // Act & Assert
            var exception = Record.Exception(() => _viewModel.Dispose());
            Assert.Null(exception);
        }

        [Fact]
        public void StateTransitions_ConnectedToBusy_UpdatesCommandCanExecute()
        {
            // Arrange
            _viewModel.IsConnected = true;
            _viewModel.IsBusy = false;
            var initialCanExecute = _viewModel.DumpMemoryCommand.CanExecute(null);

            // Act
            _viewModel.IsBusy = true;
            var finalCanExecute = _viewModel.DumpMemoryCommand.CanExecute(null);

            // Assert
            Assert.True(initialCanExecute);
            Assert.False(finalCanExecute);
        }

        [Fact]
        public void StateTransitions_PayloadSelection_UpdatesInstallCommandCanExecute()
        {
            // Arrange
            _viewModel.IsConnected = true;
            _viewModel.IsBusy = false;
            _viewModel.SelectedPayload = null;
            var initialCanExecute = _viewModel.InstallStagerCommand.CanExecute(null);

            // Act
            _viewModel.SelectedPayload = new PayloadInfo { Name = "test.bin" };
            var finalCanExecute = _viewModel.InstallStagerCommand.CanExecute(null);

            // Assert
            Assert.False(initialCanExecute);
            Assert.True(finalCanExecute);
        }
    }
}