using System;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Moq;
using S7.Core.Abstractions.Services;
using S7.Utils;
using S7_Csharp_Utility.Services;
using S7_Csharp_Utility.ViewModels;
using Xunit;

namespace S7_Csharp_Utility.Tests.ViewModels
{
    /// <summary>
    /// Unit tests for PlcConnectionViewModel focusing on UI state management and property changes.
    /// Business logic testing is handled by service layer tests.
    /// </summary>
    public class PlcConnectionViewModelTests : IDisposable
    {
        private readonly Mock<ILogger<PlcConnectionViewModel>> _mockLogger;
        private readonly Mock<ICommunicationChannelService> _mockCommunicationChannelService;
        private readonly Mock<SocatService> _mockSocatService;
        private readonly PlcConnectionViewModel _viewModel;

        public PlcConnectionViewModelTests()
        {
            _mockLogger = new Mock<ILogger<PlcConnectionViewModel>>();
            _mockCommunicationChannelService = new Mock<ICommunicationChannelService>();
            _mockSocatService = new Mock<SocatService>();
            
            _viewModel = new PlcConnectionViewModel(
                _mockLogger.Object,
                _mockCommunicationChannelService.Object,
                _mockSocatService.Object
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
            Assert.NotNull(_viewModel.ConnectCommand);
            Assert.NotNull(_viewModel.DisconnectCommand);
            Assert.NotNull(_viewModel.RefreshSerialPortsCommand);
            Assert.NotNull(_viewModel.AvailableSerialPorts);
            Assert.Empty(_viewModel.AvailableSerialPorts);
        }

        [Fact]
        public void Constructor_WithNullLogger_ThrowsArgumentNullException()
        {
            // Act & Assert
            Assert.Throws<ArgumentNullException>(() => 
                new PlcConnectionViewModel(null!, _mockCommunicationChannelService.Object, _mockSocatService.Object));
        }

        [Fact]
        public void Constructor_WithNullCommunicationChannelService_ThrowsArgumentNullException()
        {
            // Act & Assert
            Assert.Throws<ArgumentNullException>(() => 
                new PlcConnectionViewModel(_mockLogger.Object, null!, _mockSocatService.Object));
        }

        [Fact]
        public void Constructor_WithNullSocatService_ThrowsArgumentNullException()
        {
            // Act & Assert
            Assert.Throws<ArgumentNullException>(() => 
                new PlcConnectionViewModel(_mockLogger.Object, _mockCommunicationChannelService.Object, null!));
        }

        [Fact]
        public void PlcEndpoint_InitialValue_IsEmpty()
        {
            // Assert
            Assert.Equal(string.Empty, _viewModel.PlcEndpoint);
        }

        [Fact]
        public void PlcEndpoint_PropertyChanged_RaisesPropertyChangedEvent()
        {
            // Arrange
            var propertyChangedRaised = false;
            var newEndpoint = "192.168.1.100:102";
            _viewModel.PropertyChanged += (sender, e) =>
            {
                if (e.PropertyName == nameof(PlcConnectionViewModel.PlcEndpoint))
                    propertyChangedRaised = true;
            };

            // Act
            _viewModel.PlcEndpoint = newEndpoint;

            // Assert
            Assert.True(propertyChangedRaised);
            Assert.Equal(newEndpoint, _viewModel.PlcEndpoint);
        }

        [Fact]
        public void SelectedSerialPort_InitialValue_IsNull()
        {
            // Assert
            Assert.Null(_viewModel.SelectedSerialPort);
        }

        [Fact]
        public void SelectedSerialPort_PropertyChanged_RaisesPropertyChangedEvent()
        {
            // Arrange
            var propertyChangedRaised = false;
            var newPort = "COM1";
            _viewModel.PropertyChanged += (sender, e) =>
            {
                if (e.PropertyName == nameof(PlcConnectionViewModel.SelectedSerialPort))
                    propertyChangedRaised = true;
            };

            // Act
            _viewModel.SelectedSerialPort = newPort;

            // Assert
            Assert.True(propertyChangedRaised);
            Assert.Equal(newPort, _viewModel.SelectedSerialPort);
        }

        [Fact]
        public void BaudRate_InitialValue_Is9600()
        {
            // Assert
            Assert.Equal(9600, _viewModel.BaudRate);
        }

        [Fact]
        public void BaudRate_PropertyChanged_RaisesPropertyChangedEvent()
        {
            // Arrange
            var propertyChangedRaised = false;
            var newBaudRate = 115200;
            _viewModel.PropertyChanged += (sender, e) =>
            {
                if (e.PropertyName == nameof(PlcConnectionViewModel.BaudRate))
                    propertyChangedRaised = true;
            };

            // Act
            _viewModel.BaudRate = newBaudRate;

            // Assert
            Assert.True(propertyChangedRaised);
            Assert.Equal(newBaudRate, _viewModel.BaudRate);
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
                if (e.PropertyName == nameof(PlcConnectionViewModel.IsConnected))
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
                if (e.PropertyName == nameof(PlcConnectionViewModel.IsBusy))
                    propertyChangedRaised = true;
            };

            // Act
            _viewModel.IsBusy = true;

            // Assert
            Assert.True(propertyChangedRaised);
            Assert.True(_viewModel.IsBusy);
        }

        [Fact]
        public void UseSerialConnection_InitialValue_IsFalse()
        {
            // Assert
            Assert.False(_viewModel.UseSerialConnection);
        }

        [Fact]
        public void UseSerialConnection_PropertyChanged_RaisesPropertyChangedEvent()
        {
            // Arrange
            var propertyChangedRaised = false;
            _viewModel.PropertyChanged += (sender, e) =>
            {
                if (e.PropertyName == nameof(PlcConnectionViewModel.UseSerialConnection))
                    propertyChangedRaised = true;
            };

            // Act
            _viewModel.UseSerialConnection = true;

            // Assert
            Assert.True(propertyChangedRaised);
            Assert.True(_viewModel.UseSerialConnection);
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
            var newMessage = "Connected successfully";
            _viewModel.PropertyChanged += (sender, e) =>
            {
                if (e.PropertyName == nameof(PlcConnectionViewModel.StatusMessage))
                    propertyChangedRaised = true;
            };

            // Act
            _viewModel.StatusMessage = newMessage;

            // Assert
            Assert.True(propertyChangedRaised);
            Assert.Equal(newMessage, _viewModel.StatusMessage);
        }

        [Fact]
        public void AvailableSerialPorts_InitialValue_IsEmptyObservableCollection()
        {
            // Assert
            Assert.NotNull(_viewModel.AvailableSerialPorts);
            Assert.IsType<ObservableCollection<string>>(_viewModel.AvailableSerialPorts);
            Assert.Empty(_viewModel.AvailableSerialPorts);
        }

        [Fact]
        public void AvailableSerialPorts_AddItem_RaisesCollectionChangedEvent()
        {
            // Arrange
            var collectionChangedRaised = false;
            var portName = "COM1";
            _viewModel.AvailableSerialPorts.CollectionChanged += (sender, e) =>
            {
                collectionChangedRaised = true;
            };

            // Act
            _viewModel.AvailableSerialPorts.Add(portName);

            // Assert
            Assert.True(collectionChangedRaised);
            Assert.Single(_viewModel.AvailableSerialPorts);
            Assert.Equal(portName, _viewModel.AvailableSerialPorts[0]);
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
            _viewModel.IsBusy = false;

            // Act
            var canExecute = _viewModel.ConnectCommand.CanExecute(null);

            // Assert
            Assert.False(canExecute);
        }

        [Fact]
        public void ConnectCommand_WhenBusy_CannotExecute()
        {
            // Arrange
            _viewModel.IsConnected = false;
            _viewModel.IsBusy = true;

            // Act
            var canExecute = _viewModel.ConnectCommand.CanExecute(null);

            // Assert
            Assert.False(canExecute);
        }

        [Fact]
        public void DisconnectCommand_WhenConnectedAndNotBusy_CanExecute()
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
        public void RefreshSerialPortsCommand_WhenNotBusy_CanExecute()
        {
            // Arrange
            _viewModel.IsBusy = false;

            // Act
            var canExecute = _viewModel.RefreshSerialPortsCommand.CanExecute(null);

            // Assert
            Assert.True(canExecute);
        }

        [Fact]
        public void RefreshSerialPortsCommand_WhenBusy_CannotExecute()
        {
            // Arrange
            _viewModel.IsBusy = true;

            // Act
            var canExecute = _viewModel.RefreshSerialPortsCommand.CanExecute(null);

            // Assert
            Assert.False(canExecute);
        }

        [Fact]
        public void StateTransitions_ConnectedToBusy_UpdatesCommandCanExecute()
        {
            // Arrange
            _viewModel.IsConnected = true;
            _viewModel.IsBusy = false;
            var initialCanExecute = _viewModel.DisconnectCommand.CanExecute(null);

            // Act
            _viewModel.IsBusy = true;
            var finalCanExecute = _viewModel.DisconnectCommand.CanExecute(null);

            // Assert
            Assert.True(initialCanExecute);
            Assert.False(finalCanExecute);
        }

        [Fact]
        public void StateTransitions_DisconnectedToConnected_UpdatesCommandCanExecute()
        {
            // Arrange
            _viewModel.IsConnected = false;
            _viewModel.IsBusy = false;
            var initialConnectCanExecute = _viewModel.ConnectCommand.CanExecute(null);
            var initialDisconnectCanExecute = _viewModel.DisconnectCommand.CanExecute(null);

            // Act
            _viewModel.IsConnected = true;
            var finalConnectCanExecute = _viewModel.ConnectCommand.CanExecute(null);
            var finalDisconnectCanExecute = _viewModel.DisconnectCommand.CanExecute(null);

            // Assert
            Assert.True(initialConnectCanExecute);
            Assert.False(initialDisconnectCanExecute);
            Assert.False(finalConnectCanExecute);
            Assert.True(finalDisconnectCanExecute);
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
            _viewModel.PlcEndpoint = "192.168.1.100:102";
            _viewModel.SelectedSerialPort = "COM1";
            _viewModel.BaudRate = 115200;
            _viewModel.IsConnected = true;
            _viewModel.UseSerialConnection = true;

            // Assert
            Assert.Contains(nameof(PlcConnectionViewModel.PlcEndpoint), propertyChangedEvents);
            Assert.Contains(nameof(PlcConnectionViewModel.SelectedSerialPort), propertyChangedEvents);
            Assert.Contains(nameof(PlcConnectionViewModel.BaudRate), propertyChangedEvents);
            Assert.Contains(nameof(PlcConnectionViewModel.IsConnected), propertyChangedEvents);
            Assert.Contains(nameof(PlcConnectionViewModel.UseSerialConnection), propertyChangedEvents);
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

        [Theory]
        [InlineData("")]
        [InlineData("   ")]
        [InlineData(null)]
        public void PlcEndpoint_WithInvalidValues_StillSetsProperty(string invalidEndpoint)
        {
            // Act
            _viewModel.PlcEndpoint = invalidEndpoint ?? string.Empty;

            // Assert
            Assert.Equal(invalidEndpoint ?? string.Empty, _viewModel.PlcEndpoint);
        }

        [Theory]
        [InlineData(0)]
        [InlineData(-1)]
        [InlineData(1000000)]
        public void BaudRate_WithInvalidValues_StillSetsProperty(int invalidBaudRate)
        {
            // Act
            _viewModel.BaudRate = invalidBaudRate;

            // Assert
            Assert.Equal(invalidBaudRate, _viewModel.BaudRate);
        }

        [Fact]
        public void Commands_WhenBusyStateChanges_RaiseCanExecuteChanged()
        {
            // Arrange
            var canExecuteChangedRaised = false;
            _viewModel.IsConnected = false;
            _viewModel.ConnectCommand.CanExecuteChanged += (sender, e) =>
            {
                canExecuteChangedRaised = true;
            };

            // Act
            _viewModel.IsBusy = true;

            // Assert
            Assert.True(canExecuteChangedRaised);
        }

        [Fact]
        public void Commands_WhenConnectionStateChanges_RaiseCanExecuteChanged()
        {
            // Arrange
            var canExecuteChangedRaised = false;
            _viewModel.IsConnected = false;
            _viewModel.ConnectCommand.CanExecuteChanged += (sender, e) =>
            {
                canExecuteChangedRaised = true;
            };

            // Act
            _viewModel.IsConnected = true;

            // Assert
            Assert.True(canExecuteChangedRaised);
        }

        [Fact]
        public void UseSerialConnection_Toggle_UpdatesConnectionMode()
        {
            // Arrange
            var initialValue = _viewModel.UseSerialConnection;

            // Act
            _viewModel.UseSerialConnection = !initialValue;

            // Assert
            Assert.NotEqual(initialValue, _viewModel.UseSerialConnection);
        }

        [Fact]
        public void SerialPortSelection_WithValidPort_UpdatesSelectedPort()
        {
            // Arrange
            var portName = "COM3";
            _viewModel.AvailableSerialPorts.Add("COM1");
            _viewModel.AvailableSerialPorts.Add("COM2");
            _viewModel.AvailableSerialPorts.Add(portName);

            // Act
            _viewModel.SelectedSerialPort = portName;

            // Assert
            Assert.Equal(portName, _viewModel.SelectedSerialPort);
        }
    }
}