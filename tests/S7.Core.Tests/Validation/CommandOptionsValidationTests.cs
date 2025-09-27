using S7.Core.Abstractions.Commands;
using S7.Core.Abstractions.Configuration;
using System;
using System.ComponentModel.DataAnnotations;
using System.IO;
using System.Linq;
using Xunit;

namespace S7.Core.Tests.Validation
{
    public class CommandOptionsValidationTests : IDisposable
    {
        private readonly string _tempDirectory;
        private readonly string _tempFile;

        public CommandOptionsValidationTests()
        {
            _tempDirectory = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString());
            Directory.CreateDirectory(_tempDirectory);
            _tempFile = Path.Combine(_tempDirectory, "test.bin");
            File.WriteAllText(_tempFile, "test content");
        }

        public void Dispose()
        {
            if (Directory.Exists(_tempDirectory))
            {
                Directory.Delete(_tempDirectory, true);
            }
        }

        #region MemoryDumpOptions Tests

        [Fact]
        public void MemoryDumpOptions_WithValidProperties_PassesValidation()
        {
            // Arrange
            var options = new S7.Core.Abstractions.Commands.MemoryDumpOptions
            {
                Address = 0x1000,
                Length = 1024,
                PayloadPath = _tempFile,
                OutputPath = _tempDirectory,
                ChannelConfig = new CommunicationChannelConfig()
            };

            // Act
            var results = options.Validate();

            // Assert
            Assert.Empty(results);
        }

        [Fact]
        public void MemoryDumpOptions_WithInvalidLength_FailsValidation()
        {
            // Arrange
            var options = new S7.Core.Abstractions.Commands.MemoryDumpOptions { Length = 3 }; // Not 4-byte aligned

            // Act
            var results = options.Validate();

            // Assert
            Assert.NotEmpty(results);
            Assert.Contains(results, r => r.MemberNames.Contains("Length") && r.ErrorMessage!.Contains("4-byte boundary"));
        }

        [Fact]
        public void MemoryDumpOptions_WithChunkSizeLargerThanLength_FailsValidation()
        {
            // Arrange
            var options = new S7.Core.Abstractions.Commands.MemoryDumpOptions
            {
                Address = 0x1000,
                Length = 1024,
                ChunkSize = 2048, // Larger than length
                PayloadPath = _tempFile,
                OutputPath = _tempDirectory,
                ChannelConfig = new CommunicationChannelConfig()
            };

            // Act
            var results = options.Validate();

            // Assert
            Assert.NotEmpty(results);
            Assert.Contains(results, r => r.ErrorMessage!.Contains("Chunk size cannot be larger than total length"));
        }

        #endregion

        #region StagerInstallOptions Tests

        [Fact]
        public void StagerInstallOptions_WithValidProperties_PassesValidation()
        {
            // Arrange
            var options = new StagerInstallOptions
            {
                PayloadPath = _tempFile,
                ChannelConfig = new CommunicationChannelConfig()
            };

            // Act
            var results = options.Validate();

            // Assert
            Assert.Empty(results);
        }

        [Fact]
        public void StagerInstallOptions_WithPowerCycleEnabledAndNoConfig_FailsValidation()
        {
            // Arrange
            var options = new StagerInstallOptions
            {
                PayloadPath = _tempFile,
                ChannelConfig = new CommunicationChannelConfig(),
                PowerCycleBeforeInstall = true,
                PowerConfig = null // Missing
            };

            // Act
            var results = options.Validate();

            // Assert
            Assert.NotEmpty(results);
            Assert.Contains(results, r => r.ErrorMessage!.Contains("Power controller configuration is required"));
        }

        [Fact]
        public void StagerInstallOptions_WithInvalidPayloadSize_FailsValidation()
        {
            // Arrange
            var options = new StagerInstallOptions
            {
                PayloadPath = _tempFile,
                ChannelConfig = new CommunicationChannelConfig(),
                MaxPayloadSize = 5 // Smaller than the test file content
            };

            // Act
            var results = options.Validate();

            // Assert
            Assert.NotEmpty(results);
            Assert.Contains(results, r => r.ErrorMessage!.Contains("exceeds maximum allowed size"));
        }

        #endregion
    }
}