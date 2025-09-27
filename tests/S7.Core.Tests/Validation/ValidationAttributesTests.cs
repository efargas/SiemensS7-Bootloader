using S7.Core.Abstractions.Validation;
using System;
using System.ComponentModel.DataAnnotations;
using System.IO;
using Xunit;

namespace S7.Core.Tests.Validation
{
    /// <summary>
    /// Unit tests for custom validation attributes.
    /// </summary>
    public class ValidationAttributesTests : IDisposable
    {
        private readonly string _tempDirectory;
        private readonly string _tempFile;

        public ValidationAttributesTests()
        {
            // Create temporary directory and file for testing
            _tempDirectory = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString());
            Directory.CreateDirectory(_tempDirectory);
            _tempFile = Path.Combine(_tempDirectory, "test.bin");
            File.WriteAllText(_tempFile, "test content");
        }

        public void Dispose()
        {
            // Clean up temporary files
            if (Directory.Exists(_tempDirectory))
            {
                Directory.Delete(_tempDirectory, true);
            }
        }

        #region HexAddressAttribute Tests

        [Theory]
        [InlineData("0x1000", true)]
        [InlineData("0X1000", true)]
        [InlineData("1000", true)]
        [InlineData("0xFFFFFFFF", true)]
        [InlineData("0x0", true)]
        [InlineData("ABCDEF", true)]
        [InlineData("abcdef", true)]
        public void HexAddressAttribute_ValidHexAddresses_ReturnsValid(string value, bool expectedValid)
        {
            // Arrange
            var attribute = new HexAddressAttribute();
            var context = new ValidationContext(new object()) { MemberName = "TestProperty" };

            // Act
            var result = attribute.GetValidationResult(value, context);

            // Assert
            if (expectedValid)
            {
                Assert.Equal(System.ComponentModel.DataAnnotations.ValidationResult.Success, result);
            }
            else
            {
                Assert.NotEqual(System.ComponentModel.DataAnnotations.ValidationResult.Success, result);
            }
        }

        [Theory]
        [InlineData("")]
        [InlineData("   ")]
        [InlineData("0xGHIJ")]
        [InlineData("xyz")]
        [InlineData("0x")]
        [InlineData("0x100000000")] // Exceeds 32-bit range
        public void HexAddressAttribute_InvalidHexAddresses_ReturnsInvalid(string value)
        {
            // Arrange
            var attribute = new HexAddressAttribute();
            var context = new ValidationContext(new object()) { MemberName = "TestProperty" };

            // Act
            var result = attribute.GetValidationResult(value, context);

            // Assert
            Assert.NotEqual(System.ComponentModel.DataAnnotations.ValidationResult.Success, result);
            Assert.NotNull(result);
            Assert.Contains("valid hexadecimal address", result.ErrorMessage);
        }

        [Fact]
        public void HexAddressAttribute_WithMinMaxRange_ValidatesCorrectly()
        {
            // Arrange
            var attribute = new HexAddressAttribute { MinValue = 0x1000, MaxValue = 0x2000 };
            var context = new ValidationContext(new object()) { MemberName = "TestProperty" };

            // Act & Assert - Valid range
            var validResult = attribute.GetValidationResult("0x1500", context);
            Assert.Equal(System.ComponentModel.DataAnnotations.ValidationResult.Success, validResult);

            // Act & Assert - Below minimum
            var belowMinResult = attribute.GetValidationResult("0x500", context);
            Assert.NotEqual(System.ComponentModel.DataAnnotations.ValidationResult.Success, belowMinResult);
            Assert.NotNull(belowMinResult);
            Assert.Contains("between 0x1000 and 0x2000", belowMinResult.ErrorMessage);

            // Act & Assert - Above maximum
            var aboveMaxResult = attribute.GetValidationResult("0x3000", context);
            Assert.NotEqual(System.ComponentModel.DataAnnotations.ValidationResult.Success, aboveMaxResult);
            Assert.NotNull(aboveMaxResult);
            Assert.Contains("between 0x1000 and 0x2000", aboveMaxResult.ErrorMessage);
        }

        [Fact]
        public void HexAddressAttribute_WithNullValue_ReturnsValid()
        {
            // Arrange
            var attribute = new HexAddressAttribute();
            var context = new ValidationContext(new object()) { MemberName = "TestProperty" };

            // Act
            var result = attribute.GetValidationResult(null, context);

            // Assert
            Assert.Equal(System.ComponentModel.DataAnnotations.ValidationResult.Success, result);
        }

        #endregion

        #region FilePathAttribute Tests

        [Fact]
        public void FilePathAttribute_WithExistingFile_ReturnsValid()
        {
            // Arrange
            var attribute = new FilePathAttribute { MustExist = true };
            var context = new ValidationContext(new object()) { MemberName = "TestProperty" };

            // Act
            var result = attribute.GetValidationResult(_tempFile, context);

            // Assert
            Assert.Equal(System.ComponentModel.DataAnnotations.ValidationResult.Success, result);
        }

        [Fact]
        public void FilePathAttribute_WithNonExistentFile_ReturnsInvalid()
        {
            // Arrange
            var attribute = new FilePathAttribute { MustExist = true };
            var context = new ValidationContext(new object()) { MemberName = "TestProperty" };
            var nonExistentFile = Path.Combine(_tempDirectory, "nonexistent.txt");

            // Act
            var result = attribute.GetValidationResult(nonExistentFile, context);

            // Assert
            Assert.NotEqual(System.ComponentModel.DataAnnotations.ValidationResult.Success, result);
            Assert.NotNull(result);
            Assert.Contains("must specify an existing", result.ErrorMessage);
        }

        [Theory]
        [InlineData(".txt", "test.txt", true)]
        [InlineData(".bin", "test.bin", true)]
        [InlineData(".txt", "test.bin", false)]
        [InlineData(".txt,.bin", "test.txt", true)]
        [InlineData(".txt,.bin", "test.bin", true)]
        [InlineData(".txt,.bin", "test.exe", false)]
        public void FilePathAttribute_WithAllowedExtensions_ValidatesCorrectly(string allowedExtensions, string fileName, bool expectedValid)
        {
            // Arrange
            var attribute = new FilePathAttribute { MustExist = false, AllowedExtensions = allowedExtensions.Split(',') };
            var context = new ValidationContext(new object()) { MemberName = "TestProperty" };
            var filePath = Path.Combine(_tempDirectory, fileName);

            // Act
            var result = attribute.GetValidationResult(filePath, context);

            // Assert
            if (expectedValid)
            {
                Assert.Equal(System.ComponentModel.DataAnnotations.ValidationResult.Success, result);
            }
            else
            {
                Assert.NotEqual(System.ComponentModel.DataAnnotations.ValidationResult.Success, result);
                Assert.NotNull(result);
                Assert.Contains("following extensions", result.ErrorMessage);
            }
        }

        [Theory]
        [InlineData("")]
        [InlineData("   ")]
        [InlineData("invalid|path")]
        [InlineData("path\0with\0nulls")]
        public void FilePathAttribute_WithInvalidPaths_ReturnsInvalid(string invalidPath)
        {
            // Arrange
            var attribute = new FilePathAttribute();
            var context = new ValidationContext(new object()) { MemberName = "TestProperty" };

            // Act
            var result = attribute.GetValidationResult(invalidPath, context);

            // Assert
            Assert.NotEqual(System.ComponentModel.DataAnnotations.ValidationResult.Success, result);
            Assert.Contains("valid file path", result.ErrorMessage);
        }

        #endregion

        #region NetworkEndpointAttribute Tests

        [Theory]
        [InlineData("192.168.1.1:80", true)]
        [InlineData("localhost:8080", true)]
        [InlineData("example.com:443", true)]
        [InlineData("127.0.0.1:1234", true)]
        [InlineData("::1:8080", true)] // IPv6 localhost
        [InlineData("[::1]:8080", true)] // IPv6 with brackets
        public void NetworkEndpointAttribute_ValidEndpoints_ReturnsValid(string endpoint, bool expectedValid)
        {
            // Arrange
            var attribute = new NetworkEndpointAttribute();
            var context = new ValidationContext(new object()) { MemberName = "TestProperty" };

            // Act
            var result = attribute.GetValidationResult(endpoint, context);

            // Assert
            if (expectedValid)
            {
                Assert.Equal(System.ComponentModel.DataAnnotations.ValidationResult.Success, result);
            }
            else
            {
                Assert.NotEqual(System.ComponentModel.DataAnnotations.ValidationResult.Success, result);
            }
        }

        [Theory]
        [InlineData("")]
        [InlineData("   ")]
        [InlineData("192.168.1.1")]
        [InlineData(":8080")]
        [InlineData("192.168.1.1:")]
        [InlineData("192.168.1.1:99999")]
        [InlineData("invalid-host:80")]
        [InlineData("192.168.1.1:abc")]
        public void NetworkEndpointAttribute_InvalidEndpoints_ReturnsInvalid(string endpoint)
        {
            // Arrange
            var attribute = new NetworkEndpointAttribute();
            var context = new ValidationContext(new object()) { MemberName = "TestProperty" };

            // Act
            var result = attribute.GetValidationResult(endpoint, context);

            // Assert
            Assert.NotEqual(System.ComponentModel.DataAnnotations.ValidationResult.Success, result);
            Assert.Contains("valid network endpoint", result.ErrorMessage);
        }

        [Fact]
        public void NetworkEndpointAttribute_WithPortRange_ValidatesCorrectly()
        {
            // Arrange
            var attribute = new NetworkEndpointAttribute { MinPort = 8000, MaxPort = 9000 };
            var context = new ValidationContext(new object()) { MemberName = "TestProperty" };

            // Act & Assert - Valid port range
            var validResult = attribute.GetValidationResult("localhost:8500", context);
            Assert.Equal(System.ComponentModel.DataAnnotations.ValidationResult.Success, validResult);

            // Act & Assert - Below minimum port
            var belowMinResult = attribute.GetValidationResult("localhost:7000", context);
            Assert.NotEqual(System.ComponentModel.DataAnnotations.ValidationResult.Success, belowMinResult);
            Assert.NotNull(belowMinResult);
            Assert.Contains("between 8000 and 9000", belowMinResult.ErrorMessage);

            // Act & Assert - Above maximum port
            var aboveMaxResult = attribute.GetValidationResult("localhost:10000", context);
            Assert.NotEqual(System.ComponentModel.DataAnnotations.ValidationResult.Success, aboveMaxResult);
            Assert.NotNull(aboveMaxResult);
            Assert.Contains("between 8000 and 9000", aboveMaxResult.ErrorMessage);
        }

        #endregion

        #region NumericRangeAttribute Tests

        [Theory]
        [InlineData(50, 1, 100, true)]
        [InlineData(1, 1, 100, true)]
        [InlineData(100, 1, 100, true)]
        [InlineData(0, 1, 100, false)]
        [InlineData(101, 1, 100, false)]
        public void NumericRangeAttribute_WithIntegerValues_ValidatesCorrectly(int value, int min, int max, bool expectedValid)
        {
            // Arrange
            var attribute = new NumericRangeAttribute(min, max);
            var context = new ValidationContext(new object()) { MemberName = "TestProperty" };

            // Act
            var result = attribute.GetValidationResult(value, context);

            // Assert
            if (expectedValid)
            {
                Assert.Equal(System.ComponentModel.DataAnnotations.ValidationResult.Success, result);
            }
            else
            {
                Assert.NotEqual(System.ComponentModel.DataAnnotations.ValidationResult.Success, result);
                Assert.NotNull(result);
                Assert.Contains($"between {min} and {max}", result.ErrorMessage);
            }
        }

        [Theory]
        [InlineData(1024, 4, true)]  // 1024 is divisible by 4
        [InlineData(1028, 4, true)]  // 1028 is divisible by 4
        [InlineData(1025, 4, false)] // 1025 is not divisible by 4
        [InlineData(1026, 4, false)] // 1026 is not divisible by 4
        public void NumericRangeAttribute_WithAlignment_ValidatesCorrectly(int value, int alignment, bool expectedValid)
        {
            // Arrange
            var attribute = new NumericRangeAttribute(0, 10000) { Alignment = alignment };
            var context = new ValidationContext(new object()) { MemberName = "TestProperty" };

            // Act
            var result = attribute.GetValidationResult(value, context);

            // Assert
            if (expectedValid)
            {
                Assert.Equal(System.ComponentModel.DataAnnotations.ValidationResult.Success, result);
            }
            else
            {
                Assert.NotEqual(System.ComponentModel.DataAnnotations.ValidationResult.Success, result);
                Assert.NotNull(result);
                Assert.Contains($"divisible by {alignment}", result.ErrorMessage);
            }
        }

        [Fact]
        public void NumericRangeAttribute_WithNullValue_ReturnsValid()
        {
            // Arrange
            var attribute = new NumericRangeAttribute(1, 100);
            var context = new ValidationContext(new object()) { MemberName = "TestProperty" };

            // Act
            var result = attribute.GetValidationResult(null, context);

            // Assert
            Assert.Equal(System.ComponentModel.DataAnnotations.ValidationResult.Success, result);
        }

        [Fact]
        public void NumericRangeAttribute_WithNonNumericValue_ReturnsInvalid()
        {
            // Arrange
            var attribute = new NumericRangeAttribute(1, 100);
            var context = new ValidationContext(new object()) { MemberName = "TestProperty" };

            // Act
            var result = attribute.GetValidationResult("not a number", context);

            // Assert
            Assert.NotEqual(System.ComponentModel.DataAnnotations.ValidationResult.Success, result);
            Assert.Contains("numeric value", result.ErrorMessage);
        }

        #endregion

        #region TimeoutAttribute Tests

        [Theory]
        [InlineData(5000, 1000, 60000, true)]   // 5 seconds, valid range
        [InlineData(30000, 1000, 60000, true)]  // 30 seconds, valid range
        [InlineData(60000, 1000, 60000, true)]  // 60 seconds, at maximum
        [InlineData(500, 1000, 60000, false)]   // Below minimum
        [InlineData(70000, 1000, 60000, false)] // Above maximum
        public void TimeoutAttribute_WithVariousValues_ValidatesCorrectly(int timeoutMs, int minMs, int maxMs, bool expectedValid)
        {
            // Arrange
            var attribute = new TimeoutAttribute { MinTimeoutMs = minMs, MaxTimeoutMs = maxMs };
            var context = new ValidationContext(new object()) { MemberName = "TestProperty" };

            // Act
            var result = attribute.GetValidationResult(timeoutMs, context);

            // Assert
            if (expectedValid)
            {
                Assert.Equal(System.ComponentModel.DataAnnotations.ValidationResult.Success, result);
            }
            else
            {
                Assert.NotEqual(System.ComponentModel.DataAnnotations.ValidationResult.Success, result);
                Assert.NotNull(result);
                Assert.Contains("timeout", result.ErrorMessage);
            }
        }

        [Fact]
        public void TimeoutAttribute_WithDefaultRange_UsesStandardValues()
        {
            // Arrange
            var attribute = new TimeoutAttribute();
            var context = new ValidationContext(new object()) { MemberName = "TestProperty" };

            // Act & Assert - Valid default range (typically 1 second to 5 minutes)
            var validResult = attribute.GetValidationResult(30000, context); // 30 seconds
            Assert.Equal(System.ComponentModel.DataAnnotations.ValidationResult.Success, validResult);

            // Act & Assert - Below default minimum
            var belowMinResult = attribute.GetValidationResult(500, context); // 0.5 seconds
            Assert.NotEqual(System.ComponentModel.DataAnnotations.ValidationResult.Success, belowMinResult);

            // Act & Assert - Above default maximum
            var aboveMaxResult = attribute.GetValidationResult(600000, context); // 10 minutes
            Assert.NotEqual(System.ComponentModel.DataAnnotations.ValidationResult.Success, aboveMaxResult);
        }

        [Fact]
        public void TimeoutAttribute_WithNullValue_ReturnsValid()
        {
            // Arrange
            var attribute = new TimeoutAttribute();
            var context = new ValidationContext(new object()) { MemberName = "TestProperty" };

            // Act
            var result = attribute.GetValidationResult(null, context);

            // Assert
            Assert.Equal(System.ComponentModel.DataAnnotations.ValidationResult.Success, result);
        }

        [Fact]
        public void TimeoutAttribute_WithNonNumericValue_ReturnsInvalid()
        {
            // Arrange
            var attribute = new TimeoutAttribute();
            var context = new ValidationContext(new object()) { MemberName = "TestProperty" };

            // Act
            var result = attribute.GetValidationResult("not a number", context);

            // Assert
            Assert.NotEqual(System.ComponentModel.DataAnnotations.ValidationResult.Success, result);
            Assert.Contains("numeric timeout value", result.ErrorMessage);
        }

        #endregion

        #region Error Message Customization Tests

        [Fact]
        public void ValidationAttributes_WithCustomErrorMessages_UsesCustomMessages()
        {
            // Arrange
            var hexAttribute = new HexAddressAttribute { ErrorMessage = "Custom hex error message" };
            var fileAttribute = new FilePathAttribute { ErrorMessage = "Custom file error message" };
            var networkAttribute = new NetworkEndpointAttribute { ErrorMessage = "Custom network error message" };
            var numericAttribute = new NumericRangeAttribute(1, 100) { ErrorMessage = "Custom numeric error message" };
            var timeoutAttribute = new TimeoutAttribute { ErrorMessage = "Custom timeout error message" };

            var context = new ValidationContext(new object()) { MemberName = "TestProperty" };

            // Act & Assert
            var hexResult = hexAttribute.GetValidationResult("invalid", context);
            Assert.Contains("Custom hex error message", hexResult.ErrorMessage);

            var fileResult = fileAttribute.GetValidationResult("invalid|path", context);
            Assert.Contains("Custom file error message", fileResult.ErrorMessage);

            var networkResult = networkAttribute.GetValidationResult("invalid", context);
            Assert.Contains("Custom network error message", networkResult.ErrorMessage);

            var numericResult = numericAttribute.GetValidationResult(200, context);
            Assert.Contains("Custom numeric error message", numericResult.ErrorMessage);

            var timeoutResult = timeoutAttribute.GetValidationResult(-1, context);
            Assert.Contains("Custom timeout error message", timeoutResult.ErrorMessage);
        }

        #endregion
    }
}