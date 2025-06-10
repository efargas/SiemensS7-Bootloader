(* PLC Program for Modbus TCP Controlled Output *)
(*
  This program controls a physical output (Y0) based on the state
  of a Modbus accessible coil (M8000).

  - M8000: Internal auxiliary relay coil. This coil should be configured
             to be accessible via Modbus TCP (e.g., as Modbus coil 00001
             or another address depending on PLC/module mapping).
             The external client (e.g., switch_power.py) will write to this coil.
  - Y0: Physical output of the PLC that controls the power supply.
        (Ensure this output is appropriate for your application)
*)

// Main program loop (implicitly continuous scan in PLC)

IF M8000 THEN // Check if the Modbus control coil M8000 is ON
  SET Y0;     // Turn ON the physical output Y0
ELSE
  RST Y0;     // Turn OFF the physical output Y0
END_IF;

(* End of Program *)
