// Arduino sketch for controlling a power supply relay via serial commands.

// Define the pin connected to the relay's control input.
// Common choices are digital pins 2-13.
const int relayPin = 7;

// Define a small delay in milliseconds to allow the relay to mechanically settle
// after being switched. This can help prevent issues with rapid on/off cycles.
const int relaySettleDelay = 100;

// --- Setup Function ---
// This function runs once when the Arduino starts up or is reset.
void setup() {
  // Initialize serial communication.
  // The baud rate (bits per second) must match the rate used by the
  // Python script sending the commands (e.g., switch_power.py).
  // Common baud rates are 9600, 19200, 57600, 115200.
  Serial.begin(9600);

  // Configure the relayPin as an OUTPUT.
  pinMode(relayPin, OUTPUT);

  // Set the initial state of the relay.
  // IMPORTANT: Relay modules can be ACTIVE-HIGH or ACTIVE-LOW.
  // - ACTIVE-HIGH: Relay turns ON when the control pin is HIGH, OFF when LOW.
  // - ACTIVE-LOW: Relay turns ON when the control pin is LOW, OFF when HIGH.
  // This sketch assumes an ACTIVE-HIGH relay by default.
  // If your relay is ACTIVE-LOW, you should set digitalWrite(relayPin, HIGH) here
  // to ensure it's initially OFF.
  digitalWrite(relayPin, LOW); // Default to relay OFF for active-HIGH

  Serial.println("Arduino Power Control Sketch Ready.");
  Serial.println("Send 'ON' or 'OFF' (followed by newline) to control relay.");
}

// --- Loop Function ---
// This function runs repeatedly after setup() has finished.
void loop() {
  // Check if there is any data available to read from the serial port.
  if (Serial.available() > 0) {
    // Read the incoming command string until a newline character ('\n') is received.
    String command = Serial.readStringUntil('\n');
    command.trim(); // Remove any leading/trailing whitespace or carriage returns.

    if (command == "ON") {
      Serial.println("Received ON command. Activating relay...");
      // For ACTIVE-HIGH relay: HIGH turns it ON.
      // For ACTIVE-LOW relay: LOW turns it ON.
      digitalWrite(relayPin, HIGH);
      delay(relaySettleDelay); // Wait for relay to settle
      Serial.println("Relay activated.");
    } else if (command == "OFF") {
      Serial.println("Received OFF command. Deactivating relay...");
      // For ACTIVE-HIGH relay: LOW turns it OFF.
      // For ACTIVE-LOW relay: HIGH turns it OFF.
      digitalWrite(relayPin, LOW);
      delay(relaySettleDelay); // Wait for relay to settle
      Serial.println("Relay deactivated.");
    } else if (command.length() > 0) {
      // If an unknown non-empty command is received.
      Serial.print("Unknown command received: '");
      Serial.print(command);
      Serial.println("'");
      Serial.println("Please send 'ON' or 'OFF'.");
    }
    // If only a newline or whitespace was sent, command.length() might be 0
    // and it will be ignored, which is fine.
  }
}
