using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Moq;
using S7.Core.Abstractions.Services;
using S7.Net;
using S7.Services;
using S7.Utils;
using Xunit;
using S7.Core.Abstractions.Configuration;

namespace S7_Csharp_Utility.Tests.Services
{
    /// <summary>
    /// Unit tests for PlcOperationService to verify PLC operation functionality and error handling.
    /// </summary>
    public class PlcOperationServiceTests
    {
        private readonly Mock<ILogger<PlcOperationService>> _mockLogger;
        private readonly Mock<PayloadManager> _mockPayloadManager;
        private readonly PlcOperationService _service;

        public PlcOperationServiceTests()
        {
            _mockLogger = new Mock<ILogger<PlcOperationService>>();
            _mockPayloadManager = new Mock<PayloadManager>(new Mock<ILogger<PayloadManager>>().Object, null);
            _service = new PlcOperationService(_mockLogger.Object, _mockPayloadManager.Object);
        }

        [Fact]
        public void Constructor_WithNullLogger_ThrowsArgumentNullException()
        {
            // Act & Assert
            Assert.Throws<ArgumentNullException>(() => new PlcOperationService(null!, _mockPayloadManager.Object));
        }

        [Fact]
        public async Task ConnectAsync_WithNullConfig_ThrowsArgumentNullException()
        {
            // Act & Assert
            await Assert.ThrowsAsync<ArgumentNullException>(() => _service.ConnectAsync(null!, CancellationToken.None));
        }
    }
}