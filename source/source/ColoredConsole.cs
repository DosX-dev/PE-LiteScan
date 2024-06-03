// https://github.com/DosX-dev/PE-LiteScan

namespace PE_LiteScan {
    /// <summary>
    /// Provides methods for writing colored messages to the console.
    /// </summary>
    public static class ColoredConsole {

        /// <summary>
        /// Represents the different types of messages that can be written.
        /// </summary>
        private enum ColoredConsoleType {
            info = 0,
            detection = 1,
            success = 2
        }

        /// <summary>
        /// Writes an informational message to the console.
        /// </summary>
        /// <param name="message">The message to write.</param>
        public static void WriteInfo(string message) {
            WriteColoredMessage(ColoredConsoleType.info, message, String.Empty, ConsoleColor.Cyan);
        }

        /// <summary>
        /// Writes a success message to the console.
        /// </summary>
        /// <param name="message">The message to write.</param>
        public static void WriteSuccess(string message) {
            WriteColoredMessage(ColoredConsoleType.success, message, String.Empty, ConsoleColor.White);
        }

        /// <summary>
        /// Writes a bad detection message to the console.
        /// </summary>
        /// <param name="message">The message to write.</param>
        /// <param name="tip">The tip to write.</param>
        public static void WriteBadDetection(string message, string tip) {
            WriteColoredMessage(ColoredConsoleType.detection, message, tip, ConsoleColor.Red);
        }

        /// <summary>
        /// Writes a colored message to the console.
        /// </summary>
        /// <param name="type">The type of message to write.</param>
        /// <param name="message">The message to write.</param>
        /// <param name="tip">The tip to write.</param>
        /// <param name="color">The color of the message.</param>
        private static void WriteColoredMessage(ColoredConsoleType type, string message, string tip, ConsoleColor color) {
            Console.ResetColor(); // Reset the color before writing the message

            char messageTypeChar = '-'; // Default message type character

            switch (type) { // Set the message type character based on the type
                case ColoredConsoleType.info:
                    messageTypeChar = 'I'; // Informational
                    break;
                case ColoredConsoleType.detection:
                    messageTypeChar = 'X'; // Detection
                    break;
                case ColoredConsoleType.success:
                    messageTypeChar = '@'; // Success
                    break;
            }

            Console.Write($"[{messageTypeChar}] "); // Write the message type character
            Console.ForegroundColor = color;
            Console.Write(message);
            Console.ForegroundColor = ConsoleColor.White;

            if (type == ColoredConsoleType.detection) {
                Console.Write(" :: ");
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.Write(tip);
            }

            Console.WriteLine();

            Console.ResetColor();
        }
    }
}
