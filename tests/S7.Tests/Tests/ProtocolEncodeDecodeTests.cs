using FluentAssertions;
using S7.Net;
using Xunit;

namespace S7.Tests.Tests
{
    public class ProtocolEncodeDecodeTests
    {
        [Theory]
        [InlineData(new byte[] { 0x01, 0x02, 0x03 })]
        [InlineData(new byte[] { })]
        [InlineData(new byte[] { 0xFF, 0xFE, 0xFD, 0xFC, 0xFB, 0xFA })]
        public void Packet_EncodeDecode_Roundtrip(byte[] payload)
        {
            // Arrange
            var encoded = ProtocolUtils.EncodePacket(payload);

            // Act
            var decoded = ProtocolUtils.DecodePacket(encoded);

            // Assert
            decoded.Should().BeEquivalentTo(payload);
        }
    }
}