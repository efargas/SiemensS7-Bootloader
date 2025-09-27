using System;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Moq;
using NUnit.Framework;
using S7_Csharp_Utility.Interfaces;
using S7_Csharp_Utility.Models.HexViewer;
using S7_Csharp_Utility.Services.Enhanced;
using S7_Csharp_Utility.ViewModels.Enhanced;

namespace S7_Csharp_Utility.Tests.ViewModels.Enhanced
{
    /// <summary>
    /// Expert-level unit tests for EnhancedHexViewerViewModel.
    /// Demonstrates comprehensive testing strategies following TDD and BDD principles.
    /// 
    /// Test Categories:
    /// - Unit Tests: Individual method behavior
    /// - Integration Tests: Component interaction
    /// - Performance Tests: Memory and speed validation
    /// - Edge Case Tests: Boundary conditions and error scenarios
    /// - Behavioral Tests: User interaction scenarios
    /// </summary>
    [TestFixture]
    [Category("Unit")]
    public class EnhancedHexViewerViewModelTests
    {
        private Mock<IDialogService> _mockDialogService;
        private Mock<ILogger<EnhancedHexViewerViewModel>> _mockLogger;
        private EnhancedHexViewerViewModel _viewModel;
        private string _testFilePath;
        private byte[] _testData;

        [SetUp]
        public void SetUp()
        {
            _mockDialogService = new Mock<IDialogService>();
            _mockLogger = new Mock<ILogger<EnhancedHexViewerViewModel>>();
            
            // Create test data
            _testData = Enumerable.Range(0, 256).Select(i => (byte)i).ToArray();
            _testFilePath = Path.GetTempFileName();
            File.WriteAllBytes(_testFilePath, _testData);
            
            _viewModel = new EnhancedHexViewerViewModel(_mockDialogService.Object, _mockLogger.Object);
        }

        [TearDown]
        public void TearDown()
        {
            _viewModel?.Dispose();
            
            if (File.Exists(_testFilePath))
            {
                File.Delete(_testFilePath);
            }
        }

        #region Constructor Tests

        [Test]
        public void Constructor_WithValidParameters_InitializesCorrectly()
        {
            // Arrange & Act
            var viewModel = new EnhancedHexViewerViewModel(_mockDialogService.Object, _mockLogger.Object);

            // Assert
            Assert.That(viewModel.VisibleRows, Is.Not.Null);
            Assert.That(viewModel.SearchResults, Is.Not.Null);
            Assert.That(viewModel.StatusText, Is.EqualTo("Ready"));
            Assert.That(viewModel.HasData, Is.False);
            Assert.That(viewModel.IsLoading, Is.False);
            Assert.That(viewModel.ViewportRowCount, Is.EqualTo(50));
            
            // Verify commands are initialized
            Assert.That(viewModel.LoadFileCommand, Is.Not.Null);
            Assert.That(viewModel.SearchCommand, Is.Not.Null);
            Assert.That(viewModel.CopySelectionCommand, Is.Not.Null);
        }

        [Test]
        public void Constructor_WithNullDialogService_ThrowsArgumentNullException()
        {
            // Arrange, Act & Assert
            Assert.Throws<ArgumentNullException>(() => 
                new EnhancedHexViewerViewModel(null!, _mockLogger.Object));
        }

        [Test]
        public void Constructor_WithNullLogger_DoesNotThrow()
        {
            // Arrange, Act & Assert
            Assert.DoesNotThrow(() => 
                new EnhancedHexViewerViewModel(_mockDialogService.Object, null));
        }

        #endregion

        #region File Loading Tests

        [Test]
        public async Task LoadFileAsync_WithValidFile_LoadsSuccessfully()
        {
            // Arrange
            var initialStatusText = _viewModel.StatusText;

            // Act
            await _viewModel.LoadFileAsync(_testFilePath);

            // Assert
            Assert.That(_viewModel.HasData, Is.True);
            Assert.That(_viewModel.FilePath, Is.EqualTo(_testFilePath));
            Assert.That(_viewModel.IsLoading, Is.False);
            Assert.That(_viewModel.StatusText, Does.Contain("bytes"));
            Assert.That(_viewModel.TotalRows, Is.EqualTo(16)); // 256 bytes / 16 bytes per row
            Assert.That(_viewModel.VisibleRows.Count, Is.GreaterThan(0));
        }

        [Test]
        public async Task LoadFileAsync_WithNonExistentFile_HandlesErrorGracefully()
        {
            // Arrange
            var nonExistentFile = "non_existent_file.bin";

            // Act
            await _viewModel.LoadFileAsync(nonExistentFile);

            // Assert
            Assert.That(_viewModel.HasData, Is.False);
            Assert.That(_viewModel.StatusText, Does.Contain("Error"));
            Assert.That(_viewModel.IsLoading, Is.False);
            
            // Verify error dialog was shown
            _mockDialogService.Verify(d => d.ShowMessageAsync("Error", It.IsAny<string>()), Times.Once);
        }

        [Test]
        public async Task LoadFileAsync_WithNullFilePath_ShowsFileDialog()
        {
            // Arrange
            _mockDialogService.Setup(d => d.ShowOpenFileDialogAsync(
                It.IsAny<string>(), It.IsAny<string>(), It.IsAny<string>()))
                .ReturnsAsync(_testFilePath);

            // Act
            await _viewModel.LoadFileAsync(null);

            // Assert
            _mockDialogService.Verify(d => d.ShowOpenFileDialogAsync(
                "Select File to View", "*", "All Files"), Times.Once);
            Assert.That(_viewModel.HasData, Is.True);
        }

        [Test]
        public async Task LoadFileAsync_WhenUserCancelsDialog_DoesNotLoad()
        {
            // Arrange
            _mockDialogService.Setup(d => d.ShowOpenFileDialogAsync(
                It.IsAny<string>(), It.IsAny<string>(), It.IsAny<string>()))
                .ReturnsAsync((string?)null);

            // Act
            await _viewModel.LoadFileAsync(null);

            // Assert
            Assert.That(_viewModel.HasData, Is.False);
            Assert.That(_viewModel.StatusText, Is.EqualTo("Ready"));
        }

        [Test]
        public async Task LoadFileAsync_SetsIsLoadingCorrectly()
        {
            // Arrange
            var loadingStates = new List<bool>();
            _viewModel.PropertyChanged += (s, e) =>
            {
                if (e.PropertyName == nameof(_viewModel.IsLoading))
                {
                    loadingStates.Add(_viewModel.IsLoading);
                }
            };

            // Act
            await _viewModel.LoadFileAsync(_testFilePath);

            // Assert
            Assert.That(loadingStates, Contains.Item(true)); // Was set to true during loading
            Assert.That(_viewModel.IsLoading, Is.False); // Final state is false
        }

        #endregion

        #region Navigation Tests

        [Test]
        public async Task NavigateToOffset_WithValidOffset_UpdatesSelectedOffset()
        {
            // Arrange
            await _viewModel.LoadFileAsync(_testFilePath);
            var targetOffset = 100L;

            // Act
            _viewModel.NavigateToOffset(targetOffset);

            // Assert
            Assert.That(_viewModel.SelectedOffset, Is.EqualTo(targetOffset));
        }

        [Test]
        public async Task NavigateToOffset_WithNegativeOffset_DoesNotUpdate()
        {
            // Arrange
            await _viewModel.LoadFileAsync(_testFilePath);
            var initialOffset = _viewModel.SelectedOffset;

            // Act
            _viewModel.NavigateToOffset(-1);

            // Assert
            Assert.That(_viewModel.SelectedOffset, Is.EqualTo(initialOffset));
        }

        [Test]
        public async Task NavigateToOffset_WithOffsetBeyondFileSize_DoesNotUpdate()
        {
            // Arrange
            await _viewModel.LoadFileAsync(_testFilePath);
            var initialOffset = _viewModel.SelectedOffset;
            var beyondFileOffset = _testData.Length + 100;

            // Act
            _viewModel.NavigateToOffset(beyondFileOffset);

            // Assert
            Assert.That(_viewModel.SelectedOffset, Is.EqualTo(initialOffset));
        }

        [Test]
        public async Task NavigateToOffset_UpdatesViewportCorrectly()
        {
            // Arrange
            await _viewModel.LoadFileAsync(_testFilePath);
            var targetOffset = 200L; // Should be in row 12 (200/16)
            var expectedRow = targetOffset / 16;

            // Act
            _viewModel.NavigateToOffset(targetOffset);

            // Assert
            // Viewport should be centered around the target row
            var viewportCenter = _viewModel.ViewportRowCount / 2;
            var expectedViewportStart = Math.Max(0, expectedRow - viewportCenter);
            Assert.That(_viewModel.ViewportStartRow, Is.EqualTo(expectedViewportStart));
        }

        #endregion

        #region Selection Tests

        [Test]
        public async Task SelectAll_WithLoadedFile_SelectsEntireFile()
        {
            // Arrange
            await _viewModel.LoadFileAsync(_testFilePath);

            // Act
            _viewModel.SelectAll();

            // Assert
            Assert.That(_viewModel.SelectionStart, Is.EqualTo(0));
            Assert.That(_viewModel.SelectionEnd, Is.EqualTo(_testData.Length - 1));
            Assert.That(_viewModel.HasSelection, Is.True);
            Assert.That(_viewModel.SelectionLength, Is.EqualTo(_testData.Length));
        }

        [Test]
        public void SelectAll_WithoutLoadedFile_DoesNothing()
        {
            // Act
            _viewModel.SelectAll();

            // Assert
            Assert.That(_viewModel.HasSelection, Is.False);
            Assert.That(_viewModel.SelectionStart, Is.EqualTo(-1));
            Assert.That(_viewModel.SelectionEnd, Is.EqualTo(-1));
        }

        [Test]
        public async Task ClearSelection_WithActiveSelection_ClearsSelection()
        {
            // Arrange
            await _viewModel.LoadFileAsync(_testFilePath);
            _viewModel.SelectAll();
            Assert.That(_viewModel.HasSelection, Is.True); // Precondition

            // Act
            _viewModel.ClearSelection();

            // Assert
            Assert.That(_viewModel.HasSelection, Is.False);
            Assert.That(_viewModel.SelectionStart, Is.EqualTo(-1));
            Assert.That(_viewModel.SelectionEnd, Is.EqualTo(-1));
            Assert.That(_viewModel.SelectedOffset, Is.EqualTo(-1));
        }

        [Test]
        public async Task SelectionLength_CalculatesCorrectly()
        {
            // Arrange
            await _viewModel.LoadFileAsync(_testFilePath);

            // Act
            _viewModel.SelectionStart = 10;
            _viewModel.SelectionEnd = 20;

            // Assert
            Assert.That(_viewModel.SelectionLength, Is.EqualTo(11)); // 20 - 10 + 1
        }

        [Test]
        public async Task SelectionLength_WithReverseSelection_CalculatesCorrectly()
        {
            // Arrange
            await _viewModel.LoadFileAsync(_testFilePath);

            // Act
            _viewModel.SelectionStart = 20;
            _viewModel.SelectionEnd = 10;

            // Assert
            Assert.That(_viewModel.SelectionLength, Is.EqualTo(11)); // |20 - 10| + 1
        }

        #endregion

        #region Search Tests

        [Test]
        public async Task SearchAsync_WithValidPattern_FindsMatches()
        {
            // Arrange
            await _viewModel.LoadFileAsync(_testFilePath);
            _viewModel.SearchText = "00 01 02"; // Should find this pattern at the beginning

            // Act
            await _viewModel.SearchCommand.ExecuteAsync(null);

            // Assert
            Assert.That(_viewModel.SearchResults.Count, Is.GreaterThan(0));
            Assert.That(_viewModel.IsSearching, Is.False);
            Assert.That(_viewModel.StatusText, Does.Contain("matches found"));
        }

        [Test]
        public async Task SearchAsync_WithInvalidPattern_HandlesGracefully()
        {
            // Arrange
            await _viewModel.LoadFileAsync(_testFilePath);
            _viewModel.SearchText = "ZZ"; // Invalid hex

            // Act
            await _viewModel.SearchCommand.ExecuteAsync(null);

            // Assert
            Assert.That(_viewModel.StatusText, Does.Contain("Invalid search pattern"));
            Assert.That(_viewModel.IsSearching, Is.False);
        }

        [Test]
        public async Task SearchAsync_WithTextPattern_FindsMatches()
        {
            // Arrange
            var textData = System.Text.Encoding.UTF8.GetBytes("Hello World! This is a test.");
            var textFilePath = Path.GetTempFileName();
            File.WriteAllBytes(textFilePath, textData);
            
            try
            {
                await _viewModel.LoadFileAsync(textFilePath);
                _viewModel.SearchText = "World";

                // Act
                await _viewModel.SearchCommand.ExecuteAsync(null);

                // Assert
                Assert.That(_viewModel.SearchResults.Count, Is.GreaterThan(0));
                Assert.That(_viewModel.SearchResults[0].Offset, Is.EqualTo(6)); // "World" starts at offset 6
            }
            finally
            {
                File.Delete(textFilePath);
            }
        }

        [Test]
        public async Task ClearSearch_RemovesSearchResults()
        {
            // Arrange
            await _viewModel.LoadFileAsync(_testFilePath);
            _viewModel.SearchText = "00";
            await _viewModel.SearchCommand.ExecuteAsync(null);
            Assert.That(_viewModel.SearchResults.Count, Is.GreaterThan(0)); // Precondition

            // Act
            _viewModel.ClearSearchCommand.Execute(null);

            // Assert
            Assert.That(_viewModel.SearchResults.Count, Is.EqualTo(0));
            Assert.That(_viewModel.StatusText, Is.EqualTo("Ready"));
        }

        [Test]
        public async Task SelectedSearchResult_NavigatesToOffset()
        {
            // Arrange
            await _viewModel.LoadFileAsync(_testFilePath);
            _viewModel.SearchText = "00";
            await _viewModel.SearchCommand.ExecuteAsync(null);
            var firstResult = _viewModel.SearchResults.First();

            // Act
            _viewModel.SelectedSearchResult = firstResult;

            // Assert
            Assert.That(_viewModel.SelectedOffset, Is.EqualTo(firstResult.Offset));
        }

        #endregion

        #region Viewport Tests

        [Test]
        public async Task ViewportStartRow_UpdatesVisibleRows()
        {
            // Arrange
            await _viewModel.LoadFileAsync(_testFilePath);
            var initialRowCount = _viewModel.VisibleRows.Count;

            // Act
            _viewModel.ViewportStartRow = 5;
            
            // Allow async operations to complete
            await Task.Delay(100);

            // Assert
            Assert.That(_viewModel.VisibleRows.Count, Is.GreaterThan(0));
            // First visible row should start at offset 5 * 16 = 80
            if (_viewModel.VisibleRows.Count > 0)
            {
                Assert.That(_viewModel.VisibleRows[0].ByteOffset, Is.EqualTo(80));
            }
        }

        [Test]
        public async Task ViewportRowCount_UpdatesVisibleRows()
        {
            // Arrange
            await _viewModel.LoadFileAsync(_testFilePath);

            // Act
            _viewModel.ViewportRowCount = 10;
            
            // Allow async operations to complete
            await Task.Delay(100);

            // Assert
            Assert.That(_viewModel.ViewportRowCount, Is.EqualTo(10));
            // Should not exceed available rows or requested count
            Assert.That(_viewModel.VisibleRows.Count, Is.LessThanOrEqualTo(10));
        }

        [Test]
        public void ViewportRowCount_WithZeroOrNegative_ClampsToMinimum()
        {
            // Act & Assert
            _viewModel.ViewportRowCount = 0;
            Assert.That(_viewModel.ViewportRowCount, Is.EqualTo(1));

            _viewModel.ViewportRowCount = -5;
            Assert.That(_viewModel.ViewportRowCount, Is.EqualTo(1));
        }

        #endregion

        #region Command Tests

        [Test]
        public void LoadFileCommand_CanExecute_WhenNotLoading()
        {
            // Assert
            Assert.That(_viewModel.LoadFileCommand.CanExecute(null), Is.True);
        }

        [Test]
        public async Task SearchCommand_CanExecute_OnlyWhenDataLoadedAndNotSearching()
        {
            // Initially should not be able to execute
            Assert.That(_viewModel.SearchCommand.CanExecute(null), Is.False);

            // After loading file, still can't execute without search text
            await _viewModel.LoadFileAsync(_testFilePath);
            Assert.That(_viewModel.SearchCommand.CanExecute(null), Is.False);

            // With search text, should be able to execute
            _viewModel.SearchText = "test";
            Assert.That(_viewModel.SearchCommand.CanExecute(null), Is.True);
        }

        [Test]
        public async Task CopySelectionCommand_CanExecute_OnlyWithSelection()
        {
            // Initially should not be able to execute
            Assert.That(_viewModel.CopySelectionCommand.CanExecute(null), Is.False);

            // After loading file, still can't execute without selection
            await _viewModel.LoadFileAsync(_testFilePath);
            Assert.That(_viewModel.CopySelectionCommand.CanExecute(null), Is.False);

            // With selection, should be able to execute
            _viewModel.SelectionStart = 0;
            _viewModel.SelectionEnd = 10;
            Assert.That(_viewModel.CopySelectionCommand.CanExecute(null), Is.True);
        }

        #endregion

        #region Property Change Notification Tests

        [Test]
        public void PropertyChanged_FiresForAllRelevantProperties()
        {
            // Arrange
            var changedProperties = new List<string>();
            _viewModel.PropertyChanged += (s, e) => changedProperties.Add(e.PropertyName!);

            // Act
            _viewModel.SelectedOffset = 100;
            _viewModel.SelectionStart = 0;
            _viewModel.SelectionEnd = 50;
            _viewModel.SearchText = "test";
            _viewModel.IsLoading = true;
            _viewModel.StatusText = "Loading...";

            // Assert
            Assert.That(changedProperties, Contains.Item(nameof(_viewModel.SelectedOffset)));
            Assert.That(changedProperties, Contains.Item(nameof(_viewModel.SelectionStart)));
            Assert.That(changedProperties, Contains.Item(nameof(_viewModel.SelectionEnd)));
            Assert.That(changedProperties, Contains.Item(nameof(_viewModel.SelectionLength)));
            Assert.That(changedProperties, Contains.Item(nameof(_viewModel.HasSelection)));
            Assert.That(changedProperties, Contains.Item(nameof(_viewModel.SearchText)));
            Assert.That(changedProperties, Contains.Item(nameof(_viewModel.IsLoading)));
            Assert.That(changedProperties, Contains.Item(nameof(_viewModel.StatusText)));
        }

        #endregion

        #region Inspector Values Tests

        [Test]
        public async Task InspectorValues_UpdatesWhenSelectionChanges()
        {
            // Arrange
            await _viewModel.LoadFileAsync(_testFilePath);
            
            // Act
            _viewModel.SelectedOffset = 0;
            
            // Allow async operations to complete
            await Task.Delay(100);

            // Assert
            Assert.That(_viewModel.InspectorValues, Is.Not.EqualTo(InspectorValues.Empty));
            Assert.That(_viewModel.InspectorValues.Byte, Is.EqualTo(0)); // First byte should be 0
        }

        [Test]
        public async Task InspectorValues_HandlesSelectionRange()
        {
            // Arrange
            await _viewModel.LoadFileAsync(_testFilePath);
            
            // Act
            _viewModel.SelectionStart = 0;
            _viewModel.SelectionEnd = 3; // Select first 4 bytes
            
            // Allow async operations to complete
            await Task.Delay(100);

            // Assert
            Assert.That(_viewModel.InspectorValues, Is.Not.EqualTo(InspectorValues.Empty));
            Assert.That(_viewModel.InspectorValues.Int32, Is.Not.Null); // Should have 4-byte integer value
        }

        #endregion

        #region Disposal Tests

        [Test]
        public void Dispose_CleansUpResources()
        {
            // Arrange
            var viewModel = new EnhancedHexViewerViewModel(_mockDialogService.Object, _mockLogger.Object);

            // Act & Assert
            Assert.DoesNotThrow(() => viewModel.Dispose());
            
            // Verify logging occurred
            _mockLogger.Verify(
                x => x.Log(
                    LogLevel.Debug,
                    It.IsAny<EventId>(),
                    It.Is<It.IsAnyType>((v, t) => v.ToString()!.Contains("disposed")),
                    It.IsAny<Exception>(),
                    It.IsAny<Func<It.IsAnyType, Exception?, string>>()),
                Times.Once);
        }

        [Test]
        public void Dispose_CanBeCalledMultipleTimes()
        {
            // Arrange
            var viewModel = new EnhancedHexViewerViewModel(_mockDialogService.Object, _mockLogger.Object);

            // Act & Assert
            Assert.DoesNotThrow(() => viewModel.Dispose());
            Assert.DoesNotThrow(() => viewModel.Dispose());
            Assert.DoesNotThrow(() => viewModel.Dispose());
        }

        #endregion

        #region Edge Cases and Error Handling

        [Test]
        public async Task LoadFileAsync_WithEmptyFile_HandlesCorrectly()
        {
            // Arrange
            var emptyFilePath = Path.GetTempFileName();
            File.WriteAllBytes(emptyFilePath, Array.Empty<byte>());

            try
            {
                // Act
                await _viewModel.LoadFileAsync(emptyFilePath);

                // Assert
                Assert.That(_viewModel.HasData, Is.True);
                Assert.That(_viewModel.TotalRows, Is.EqualTo(0));
                Assert.That(_viewModel.VisibleRows.Count, Is.EqualTo(0));
            }
            finally
            {
                File.Delete(emptyFilePath);
            }
        }

        [Test]
        public async Task LoadFileAsync_WithVeryLargeFile_HandlesEfficiently()
        {
            // This test would require a very large file to be meaningful
            // For now, we'll test with a moderately sized file
            var largeData = new byte[1024 * 1024]; // 1MB
            for (int i = 0; i < largeData.Length; i++)
            {
                largeData[i] = (byte)(i % 256);
            }

            var largeFilePath = Path.GetTempFileName();
            File.WriteAllBytes(largeFilePath, largeData);

            try
            {
                var startTime = DateTime.UtcNow;

                // Act
                await _viewModel.LoadFileAsync(largeFilePath);

                var loadTime = DateTime.UtcNow - startTime;

                // Assert
                Assert.That(_viewModel.HasData, Is.True);
                Assert.That(loadTime.TotalSeconds, Is.LessThan(5)); // Should load within 5 seconds
                Assert.That(_viewModel.VisibleRows.Count, Is.LessThanOrEqualTo(_viewModel.ViewportRowCount));
            }
            finally
            {
                File.Delete(largeFilePath);
            }
        }

        #endregion
    }
}