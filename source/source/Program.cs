// https://github.com/DosX-dev/PE-LiteScan

namespace PE_LiteScan {
    class Program {

        /// <summary>
        /// Entry point of the program.
        /// </summary>
        /// <param name="args">Command line arguments. The first argument should be the path to the executable.</param>
        static void Main(string[] args) {
            // Print a welcome message

            Console.ForegroundColor = ConsoleColor.DarkGreen;
            Console.WriteLine("// LiteScan heuristic analyzer for PE files\n// https://github.com/DosX-dev/PE-LiteScan\n");
            Console.ResetColor();

            // Check if the correct number of arguments were passed
            if (args.Length != 1) {
                // Print usage information if the incorrect number of arguments were passed
                ColoredConsole.WriteInfo("Usage: \"path_to_exe.exe\"");
                return;
            }

            string filePath = args[0]; // Get the path to the executable

            if (!System.IO.File.Exists(filePath)) {
                Console.WriteLine("ERR:NOT_FOUND");
                return;
            }

            try {
                var analyzer = new PEAnalyzer(filePath);
                analyzer.Analyze();
            } catch (Exception ex) {
                Console.WriteLine($"Error analyzing file: {ex.Message}");
            }
        }
    }
}
