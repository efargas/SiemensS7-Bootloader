(* PLC Program for Modbus TCP Controlled Output *)
(*
  This program controls a physical output (Y0) based on the state
  of a Modbus accessible coil (M0).

  - M0: Internal auxiliary relay coil. This coil will be configured
        to be accessible via Modbus TCP as coil 0x0000 (the first coil).
        The external client (e.g., switch_power.py) will write to this coil.
  - Y0: Physical output of the PLC that controls the power supply.
        (Ensure this output is appropriate for your application)
*)

// Main program loop (implicitly continuous scan in PLC)

IF M0 THEN // Check if the Modbus control coil M0 is ON
  SET Y0;     // Turn ON the physical output Y0
ELSE
  RST Y0;     // Turn OFF the physical output Y0
END_IF;

(* End of Program *)
