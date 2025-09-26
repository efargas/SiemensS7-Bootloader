using System;
using System.ComponentModel;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Moq;
using S7.Core.Abstractions.Services;
using S7.Utils;
using S7_Csharp_Utility.ViewModels;
using Xunit;

namespace S7_Csharp_Utility.Tests.ViewModels
{
    /// <summary>
    /// Unit tests for ModbusPowerSupplyViewModel focusing on UI state management and property changes.
    /// Business logic testing is handled by service layer tests.
    /// </summary>
    public class ModbusPowerSupplyViewModelTests : IDisposable
    {
        private readonly Mock<ILogger<ModbusPowerSupplyViewModel>> _mockLogger;
        private readonly Mock<IPowerSupplyService> _mockPowerSupplyService;
        private readonly ModbusPowerSupplyViewModel _viewModel;

        public ModbusPowerSupplyViewModelTests()
        {
            _mockLogger = new Mock<ILogger<ModbusPowerSupplyViewModel>>();
            _mockPowerSupplyService = new Mock<IPowerSupplyService>();
            
            _viewModel = new ModbusPowerSupplyViewModel(_mockLogger.Object, _mockPowerSupplyService.Object);
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
            Assert.NotNull(_viewModel.TurnOnCommand);
            Assert.NotNull(_viewModel.TurnOffCommand);
            Assert.NotNull(_viewModel.PowerCycleCommand);
            Assert.NotNull(_viewModel.RefreshStatusCommand);
        }

        [Fact]
        public void Constructor_WithNullLogger_ThrowsArgumentNullException()
        {
            // Act & Assert
            Assert.Throws<ArgumentNullException>(() => 
                new ModbusPowerSupplyViewModel(null!, _mockPowerSupplyService.Object));
        }

        [Fact]
        public void Constructor_WithNullPowerSupplyService_ThrowsArgumentNullException()
        {
            // Act & Assert
            Assert.Throws<ArgumentNullException>(() => 
                new ModbusPowerSupplyViewModel(_mockLogger.Object, null!));
        }

        [Fact]
        public void Host_InitialValue_IsEmpty()
        {
            // Assert
            Assert.Equal(string.Empty, _viewModel.Host);
        }

        [Fact]
        public void Host_PropertyChanged_RaisesPropertyChangedEvent()
        {
            // Arrange
            var propertyChangedRaised = false;
            var newHost = "192.168.1.100";
            _viewModel.PropertyChanged += (sender, e) =>
            {
                if (e.PropertyName == nameof(ModbusPowerSupplyViewModel.Host))
                    propertyChangedRaised = true;
            };

            // Act
            _viewModel.Host = newHost;

            // Assert
            Assert.True(propertyChangedRaised);
            Assert.Equal(newHost, _viewModel.Host);
        }

        [Fact]
        public void Port_InitialValue_Is502()
        {
            // Assert
            Assert.Equal(502, _viewModel.Port);
        }

        [Fact]
        public void Port_PropertyChanged_RaisesPropertyChangedEvent()
        {
            // Arrange
            var propertyChangedRaised = false;
            var newPort = 1502;
            _viewModel.PropertyChanged += (sender, e) =>
            {
                if (e.PropertyName == nameof(ModbusPowerSupplyViewModel.Port))
                    propertyChangedRaised = true;
            };

            // Act
            _viewModel.Port = newPort;

            // Assert
            Assert.True(propertyChangedRaised);
            Assert.Equal(newPort, _viewModel.Port);
        }

        [Fact]
        public void SlaveId_InitialValue_Is1()
        {
            // Assert
            Assert.Equal(1, _viewModel.SlaveId);
        }

        [Fact]
        public void SlaveId_PropertyChanged_RaisesPropertyChangedEvent()
        {
            // Arrange
            var propertyChangedRaised = false;
            var newSlaveId = 2;
            _viewModel.PropertyChanged += (sender, e) =>
            {
                if (e.PropertyName == nameof(ModbusPowerSupplyViewModel.SlaveId))
                    propertyChangedRaised = true;
            };

            // Act
            _viewModel.SlaveId = newSlaveId;

            // Assert
            Assert.True(propertyChangedRaised);
            Assert.Equal(newSlaveId, _viewModel.SlaveId);
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
                if (e.PropertyName == nameof(ModbusPowerSupplyViewModel.IsConnected))
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
                if (e.PropertyName == nameof(ModbusPowerSupplyViewModel.IsBusy))
                    propertyChangedRaised = true;
            };

            // Act
            _viewModel.IsBusy = true;

            // Assert
            Assert.True(propertyChangedRaised);
            Assert.True(_viewModel.IsBusy);
        }

        [Fact]
        public void PowerStatus_InitialValue_IsUnknown()
        {
            // Assert
            Assert.Equal("Unknown", _viewModel.PowerStatus);
        }

        [Fact]
        public void PowerStatus_PropertyChanged_RaisesPropertyChangedEvent()
        {
            // Arrange
            var propertyChangedRaised = false;
            var newStatus = "On";
            _viewModel.PropertyChanged += (sender, e) =>
            {
                if (e.PropertyName == nameof(ModbusPowerSupplyViewModel.PowerStatus))
                    propertyChangedRaised = true;
            };

            // Act
            _viewModel.PowerStatus = newStatus;

            // Assert
            Assert.True(propertyChangedRaised);
            Assert.Equal(newStatus, _viewModel.PowerStatus);
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
                if (e.PropertyName == nameof(ModbusPowerSupplyViewModel.StatusMessage))
                    propertyChangedRaised = true;
            };

            // Act
            _viewModel.StatusMessage = newMessage;

            // Assert
            Assert.True(propertyChangedRaised);
            Assert.Equal(newMessage, _viewModel.StatusMessage);
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
        public void TurnOnCommand_WhenConnectedAndNotBusy_CanExecute()
        {
            // Arrange
            _viewModel.IsConnected = true;
            _viewModel.IsBusy = false;

            // Act
            var canExecute = _viewModel.TurnOnCommand.CanExecute(null);

            // Assert
            Assert.True(canExecute);
        }

        [Fact]
        public void TurnOnCommand_WhenNotConnected_CannotExecute()
        {
            // Arrange
            _viewModel.IsConnected = false;

            // Act
            var canExecute = _viewModel.TurnOnCommand.CanExecute(null);

            // Assert
            Assert.False(canExecute);
        }

        [Fact]
        public void TurnOffCommand_WhenConnectedAndNotBusy_CanExecute()
        {
            // Arrange
            _viewModel.IsConnected = true;
            _viewModel.IsBusy = false;

            // Act
            var canExecute = _viewModel.TurnOffCommand.CanExecute(null);

            // Assert
            Assert.True(canExecute);
        }

        [Fact]
        public void TurnOffCommand_WhenNotConnected_CannotExecute()
        {
            // Arrange
            _viewModel.IsConnected = false;

            // Act
            var canExecute = _viewModel.TurnOffCommand.CanExecute(null);

            // Assert
            Assert.False(canExecute);
        }

        [Fact]
        public void PowerCycleCommand_WhenConnectedAndNotBusy_CanExecute()
        {
            // Arrange
            _viewModel.IsConnected = true;
            _viewModel.IsBusy = false;

            // Act
            var canExecute = _viewModel.PowerCycleCommand.CanExecute(null);

            // Assert
            Assert.True(canExecute);
        }

        [Fact]
        public void PowerCycleCommand_WhenNotConnected_CannotExecute()
        {
            // Arrange
            _viewModel.IsConnected = false;

            // Act
            var canExecute = _viewModel.PowerCycleCommand.CanExecute(null);

            // Assert
            Assert.False(canExecute);
        }

        [Fact]
        public void RefreshStatusCommand_WhenConnectedAndNotBusy_CanExecute()
        {
            // Arrange
            _viewModel.IsConnected = true;
            _viewModel.IsBusy = false;

            // Act
            var canExecute = _viewModel.RefreshStatusCommand.CanExecute(null);

            // Assert
            Assert.True(canExecute);
        }

        [Fact]
        public void RefreshStatusCommand_WhenNotConnected_CannotExecute()
        {
            // Arrange
            _viewModel.IsConnected = false;

            // Act
            var canExecute = _viewModel.RefreshStatusCommand.CanExecute(null);

            // Assert
            Assert.False(canExecute);
        }

        [Fact]
        public void StateTransitions_ConnectedToBusy_UpdatesCommandCanExecute()
        {
            // Arrange
            _viewModel.IsConnected = true;
            _viewModel.IsBusy = false;
            var initialCanExecute = _viewModel.TurnOnCommand.CanExecute(null);

            // Act
            _viewModel.IsBusy = true;
            var finalCanExecute = _viewModel.TurnOnCommand.CanExecute(null);

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
            var initialTurnOnCanExecute = _viewModel.TurnOnCommand.CanExecute(null);

            // Act
            _viewModel.IsConnected = true;
            var finalConnectCanExecute = _viewModel.ConnectCommand.CanExecute(null);
            var finalTurnOnCanExecute = _viewModel.TurnOnCommand.CanExecute(null);

            // Assert
            Assert.True(initialConnectCanExecute);
            Assert.False(initialTurnOnCanExecute);
            Assert.False(finalConnectCanExecute);
            Assert.True(finalTurnOnCanExecute);
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
            _viewModel.Host = "192.168.1.100";
            _viewModel.Port = 1502;
            _viewModel.IsConnected = true;
            _viewModel.PowerStatus = "On";

            // Assert
            Assert.Contains(nameof(ModbusPowerSupplyViewModel.Host), propertyChangedEvents);
            Assert.Contains(nameof(ModbusPowerSupplyViewModel.Port), propertyChangedEvents);
            Assert.Contains(nameof(ModbusPowerSupplyViewModel.IsConnected), propertyChangedEvents);
            Assert.Contains(nameof(ModbusPowerSupplyViewModel.PowerStatus), propertyChangedEvents);
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
        public void Host_WithInvalidValues_StillSetsProperty(string invalidHost)
        {
            // Act
            _viewModel.Host = invalidHost ?? string.Empty;

            // Assert
            Assert.Equal(invalidHost ?? string.Empty, _viewModel.Host);
        }

        [Theory]
        [InlineData(0)]
        [InlineData(-1)]
        [InlineData(65536)]
        public void Port_WithInvalidValues_StillSetsProperty(int invalidPort)
        {
            // Act
            _viewModel.Port = invalidPort;

            // Assert
            Assert.Equal(invalidPort, _viewModel.Port);
        }

        [Theory]
        [InlineData(0)]
        [InlineData(-1)]
        [InlineData(256)]
        public void SlaveId_WithInvalidValues_StillSetsProperty(int invalidSlaveId)
        {
            // Act
            _viewModel.SlaveId = invalidSlaveId;

            // Assert
            Assert.Equal(invalidSlaveId, _viewModel.SlaveId);
        }

        [Fact]
        public void Commands_WhenBusyStateChanges_RaiseCanExecuteChanged()
        {
            // Arrange
            var canExecuteChangedRaised = false;
            _viewModel.IsConnected = true;
            _viewModel.TurnOnCommand.CanExecuteChanged += (sender, e) =>
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
    }
}