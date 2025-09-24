using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Xunit;
using S7.Utils.Interfaces;
using S7.Services;

namespace S7.Core.Tests
{
    public class VirtualFileReaderTests : IDisposable
    {
        private readonly string _testFilePath;
        private readonly byte[] _testFileContent;

        public VirtualFileReaderTests()
        {
            _testFilePath = Path.GetTempFileName();
            _testFileContent = new byte[4096];
            for (int i = 0; i < _testFileContent.Length; i++)
            {
                _testFileContent[i] = (byte)(i % 256);
            }
            File.WriteAllBytes(_testFilePath, _testFileContent);
        }

        public void Dispose()
        {
            if (File.Exists(_testFilePath))
            {
                File.Delete(_testFilePath);
            }
        }

        [Theory]
        [InlineData(typeof(MemoryMappedFileVirtualReader))]
        [InlineData(typeof(FileStreamVirtualReader))]
        public void Constructor_WithNullFilePath_ThrowsArgumentNullException(Type readerType)
        {
            var ex = Assert.Throws<System.Reflection.TargetInvocationException>(() =>
                Activator.CreateInstance(readerType, new object[] { null, 4096 })
            );
            Assert.IsType<ArgumentNullException>(ex.InnerException);
        }

        [Theory]
        [InlineData(typeof(MemoryMappedFileVirtualReader))]
        [InlineData(typeof(FileStreamVirtualReader))]
        public void Constructor_WithNonExistentFilePath_ThrowsFileNotFoundException(Type readerType)
        {
            var ex = Assert.Throws<System.Reflection.TargetInvocationException>(() =>
                Activator.CreateInstance(readerType, new object[] { "non_existent_file.tmp", 4096 })
            );
            Assert.IsType<FileNotFoundException>(ex.InnerException);
        }

        [Theory]
        [InlineData(typeof(MemoryMappedFileVirtualReader))]
        [InlineData(typeof(FileStreamVirtualReader))]
        public async Task ReadPageAsync_ReadsCorrectData(Type readerType)
        {
            // Arrange
            using var reader = (IVirtualFileReader)Activator.CreateInstance(readerType, new object[] { _testFilePath, 1024 });

            // Act
            var page = await reader.ReadPageAsync(1, 1024, CancellationToken.None);

            // Assert
            Assert.Equal(1024, page.Length);
            Assert.Equal(1, page.PageIndex);
            for (int i = 0; i < 1024; i++)
            {
                Assert.Equal((byte)((1024 + i) % 256), page.Data.Span[i]);
            }
        }

        [Theory]
        [InlineData(typeof(MemoryMappedFileVirtualReader))]
        [InlineData(typeof(FileStreamVirtualReader))]
        public async Task ReadPageAsync_WhenCancelled_ThrowsOperationCanceledException(Type readerType)
        {
            // Arrange
            using var reader = (IVirtualFileReader)Activator.CreateInstance(readerType, new object[] { _testFilePath, 1024 });
            var cts = new CancellationTokenSource();

            // Act
            // For FileStreamVirtualReader, the cancellation token is checked before the read.
            // For MemoryMappedFileVirtualReader, it's also checked before.
            // A delay inside the read is not possible without a mock, but we can cancel before the call.
            cts.Cancel();

            // Assert
            await Assert.ThrowsAsync<OperationCanceledException>(() => reader.ReadPageAsync(0, 1024, cts.Token));
        }
    }
}
