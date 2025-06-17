(* PLC Configuration Program *)
(* This program should be run once after download, driven by M8411. *)
(* A PLC power cycle is required AFTER this program has been run *)
(* and parameters have been written to flash. *)

IF M8411 THEN // M8411: Built-in flag for saving communication parameters

  // Segment 1: Set PLC IP Address to 192.168.1.18
  // D8470: IP Address Segment 1 (High Byte), Segment 2 (Low Byte)
  // D8471: IP Address Segment 3 (High Byte), Segment 4 (Low Byte)
  D8470 := H_C0A8; // 192.168
  D8471 := H_0112; // 1.18

  // Segment 2: Configure Modbus TCP Coil Mapping
  // Map M0 as the first Modbus coil (address 0x0000)
  // This maps a block of 32 M-coils starting from M0.
  // D8476: Bit 15-13 (Number of Points), Bit 12-0 (Starting Address Type/Offset)
  // Upper 3 bits '001' = 1 * 32 points.
  // Lower 13 bits '0000100000000' (0x0080) = M element, starting at M0.
  D8476 := H_2080; // Map M0...M31 to Modbus Coils 0x0000 - 0x001F

END_IF;

(* End of Configuration Program *)
