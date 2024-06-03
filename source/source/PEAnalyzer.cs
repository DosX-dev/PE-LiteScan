// https://github.com/DosX-dev/PE-LiteScan

using PeNet;
using PeNet.Header.Pe;
using System.Text;

namespace PE_LiteScan {
    public class PEAnalyzer {
        private readonly string _filePath = String.Empty;
        private readonly byte[] _fileBytes = { };
        private readonly PeFile _peFile;

        private bool badDetected = false;

        // List of known packers/protectors signatures and their corresponding section names
        private static readonly List<(string Packer, string Version, string SectionName)> KnownSections = new List<(string Packer, string Version, string SectionName)>
        {
            ("UPX", String.Empty, "UPX0"),
            ("UPX", String.Empty, "UPX1"),
            ("UPX", String.Empty, "UPX2"),
            ("UPX", String.Empty, "UPX3"),
            ("VMProtect", String.Empty, ".vmp"),
            ("VMProtect", String.Empty, ".vmp0"),
            ("VMProtect", String.Empty, ".vmp1"),
            ("VMProtect", String.Empty, ".vmp2"),
            ("VMProtect", String.Empty, ".vmp3"),
            ("ASPack", "1.08-2.XX", ".adata"),
            ("ASPack", "2.XX", ".aspack"),
            ("Petite", String.Empty, ".petite"),
            ("Petite", String.Empty, "petite"),
            ("Enigma", String.Empty, ".enigma1"),
            ("Enigma", String.Empty, ".enigma2"),
            (".NET Reactor", "2.XX", ".reacto"),
            ("Themida", "3.X", ".imports"),
            ("Themida", "3.X", ".themida"),
            ("Themida", "3.X", ".winlice"),
            ("Themida", "3.X", ".loadcon"),
            ("ASM Guard", "2.XX", "ASMGUARD"),
            ("ASM Guard", "2.XX", ".asmg"),
            ("tElock", String.Empty, "UPX!"),
            ("YodasProtector", "1.0b", ".yP"),
            ("YodasCrypter", "1.X", "yC"),
            ("MPRESS", String.Empty, ".MPRESS1"),
            ("MPRESS", String.Empty, ".MPRESS2"),
            ("DxPack", "1.0", "coderpub"),
            ("SafeNet", String.Empty, ".AKS1"),
            ("SafeNet", String.Empty, ".AKS2"),
            ("SafeNet", String.Empty, ".AKS3"),
            ("Alienyze", String.Empty, ".alien"),
            ("PECompact", String.Empty, "pec"),
            ("PECompact", String.Empty, "pec1"),
            ("RLP", String.Empty, ".rlp"),
            (".NET Reactor", String.Empty, ".reacto"),
            ("StarForce", "4.X-5.X", ".ps4"),
            ("StarForce", "3.X", ".sforce3"),
            ("Safengine Shielden", String.Empty, ".sedat"),
            ("VirtualizeProtect", String.Empty, "VProtect"),
            ("Krypton", String.Empty        , "YADO"),
            ("NsPack", String.Empty, "nsp0"),
            ("NsPack", String.Empty, "nsp1"),
            ("nPack", String.Empty, ".nPack"),
            ("JDPack", String.Empty, ".jdpack"),
            ("SC Pack", String.Empty, ".scpack"),
            ("Simple Pack", String.Empty, ".spack"),
            ("Eronana", String.Empty, ".packer"),
            ("PE-SHiELD", String.Empty, "PESHiELD"),
            ("SVK Protector", String.Empty, "SVKP"),
            ("obfus.h", String.Empty, ".obfh"),
            ("Warbird", String.Empty, "?g_Encry"),
            ("ACProtect", String.Empty, ".perplex"),
            ("Software Compress", String.Empty, "SoftComp"),
            ("RLPack", String.Empty, ".RLPack"),
            ("CodeVirtualizer", String.Empty, ".vlizer"),
            ("DYAMAR", "1.3.5", ".dyamarC"),
            ("hmimys", "1.3", "hmimys"),
            ("Morphnah", "1.0.X", ".nah"),
            ("DNGuard", String.Empty, ".I:R")
        };

        public PEAnalyzer(string filePath) { // Initialize the analyzer
            _filePath = filePath;
            _fileBytes = System.IO.File.ReadAllBytes(filePath);
            _peFile = new PeFile(filePath);
        }

        /// <summary>
        /// Analyzes the PE file and outputs the results
        /// </summary>
        public void Analyze() {
            ColoredConsole.WriteInfo($"Arch: {(_peFile.Is64Bit ? "x64" : (_peFile.Is32Bit ? "x32" : "-"))}; App type: {(_peFile.IsDll ? "DLL" : "EXE")}; Platform: {(_peFile.IsDotNet ? ".NET" : "Native")}");

            CheckCustomDosStub(); // Check if the DOS stub contains any custom DOS stubs
            CheckEntropy(); // Check the entropy of the file
            CheckEntryPoint(); // Check the entry point of the file
            CheckTextSection(); // Check if the PE file contains a .text section
            CheckImports(); // Check if the import table exists in the PE file
            CheckSections(); // Check if the sections of the PE file are valid
            CheckOverlay(); // Check for an overlay in the file

            if (_peFile.IsDotNet) {
                CheckNetForIldasm(); // Check if the file contains the 'SuppressIldasmAttribute' attribute
            } else {
                CheckEntryPointPosition(); // Check if the entry point of the PE file is located in the last section
            }

            if (!badDetected) {
                ColoredConsole.WriteSuccess("Heuristic analysis did not find anything anomalous");
            }
        }


        /// <summary>
        /// This method checks if the entry point of the PE file is located in the last section.
        /// </summary>
        public void CheckEntryPointPosition() {
            if (_peFile?.ImageSectionHeaders?.Count() > 1 && !_peFile.IsDotNet) {
                ImageSectionHeader lastSection = _peFile.ImageSectionHeaders.Last(); // Get the last section

                if (_peFile.ImageNtHeaders != null) {
                    uint entryPoint = _peFile.ImageNtHeaders.OptionalHeader.AddressOfEntryPoint; // Get the address of the entry point

                    if (entryPoint >= lastSection.VirtualAddress && entryPoint < lastSection.VirtualAddress + lastSection.SizeOfRawData) { // Check if the entry point is in the last section
                        ColoredConsole.WriteBadDetection("LAST_SECTION_ENTRYPOINT", "The entry point is in the last section");
                        badDetected = true;
                    }
                }
            }
        }


        /// <summary>
        /// Checks if the PE file contains a .text section.
        /// </summary>
        private void CheckTextSection() {
            if (_peFile.ImageSectionHeaders == null || !_peFile.ImageSectionHeaders.Any(s => s.Name == ".text")) { // Check if there are any sections with the .text name
                ColoredConsole.WriteBadDetection("NO_TEXT_SECTION", "The .text section is missing");
                badDetected = true;
            }
        }


        /// <summary>
        /// Checks for an overlay in the file. An overlay is a portion of the file that is appended after the main executable content.
        /// </summary>
        private void CheckOverlay() {
            // Check if there are any Image Section Headers
            if (_peFile.ImageSectionHeaders != null) {
                // Get the last section header
                var lastSection = _peFile.ImageSectionHeaders.OrderByDescending(s => s.PointerToRawData).FirstOrDefault();
                // If there is no last section, return
                if (lastSection == null) {
                    return; // What?
                }

                // Calculate the offset of the overlay
                uint overlayOffset = lastSection.PointerToRawData + lastSection.SizeOfRawData;

                using (var fs = new FileStream(_filePath, FileMode.Open, FileAccess.Read)) {
                    // If the file size is less than or equal to the overlay offset, there is no overlay
                    if (fs.Length <= overlayOffset) {
                        return; // No overlay
                    }

                    fs.Seek(overlayOffset, SeekOrigin.Begin);
                    var overlaySize = fs.Length - overlayOffset;
                    byte[] overlay = new byte[overlaySize];
                    fs.Read(overlay, 0, (int)overlaySize);

                    // Calculate the entropy of the overlay
                    double overlayEntropy = EntropyCalculator.Calc(overlay);

                    // If the overlay entropy is greater than 7.5, it may contain compressed data
                    if (overlayEntropy > 7.5) {
                        ColoredConsole.WriteBadDetection($"STRANGE_OVERLAY", "Seems like compressed data in overlay");
                        badDetected = true;
                    }
                }
            }
        }


        /// <summary>
        /// Checks the entropy of the file. High entropy values suggest that the file may be packed.
        /// </summary>
        private void CheckEntropy() {
            // Calculate the entropy of the file
            double entropy = EntropyCalculator.Calc(_fileBytes);

            // If the entropy is greater than 7.5, the file may be packed
            if (entropy > 7.5) {
                ColoredConsole.WriteBadDetection("HIGH_ENTROPY", "Seems like file contains a packed data");
                badDetected = true;
            }
        }


        /// <summary>
        /// Checks if the given file contains the 'SuppressIldasmAttribute' attribute, which indicates that the file is protected against ILDASM.
        /// </summary>
        private void CheckNetForIldasm() {
            // Create a new signature scanner for the file
            var signatureScanner = new SignatureScanner(_fileBytes);

            // Check if the file contains the 'SuppressIldasmAttribute' attribute
            bool containsIldasm = signatureScanner.ContainsSignature("00 'SuppressIldasmAttribute' 00");

            // If the file contains the attribute, write a bad detection message
            if (containsIldasm) {
                ColoredConsole.WriteBadDetection("NET_ANTI_ILDASM", "Build has a SuppressIldasmAttribute attribute");
                badDetected = true;
            }
        }

        /// <summary>
        /// Checks the entry point of the file to see if it is a strange entry point.
        /// </summary>
        private void CheckEntryPoint() {
            // Check if the file has image section headers and image NT headers
            if (_peFile.ImageSectionHeaders != null && _peFile.ImageNtHeaders != null) {
                // Get the address of the entry point
                uint entryPointRVA = _peFile.ImageNtHeaders.OptionalHeader.AddressOfEntryPoint;

                // Check if the entry point is not at the start of the file
                if (entryPointRVA != 0) {
                    // Find the section that contains the entry point
                    var entryPointSection = _peFile.ImageSectionHeaders.First(s => s.VirtualAddress <= entryPointRVA && entryPointRVA < s.VirtualAddress + s.VirtualSize);

                    // Calculate the offset of the entry point within the section
                    long entryPointOffset = entryPointSection.PointerToRawData + (entryPointRVA - entryPointSection.VirtualAddress);

                    // Check if the first byte at the entry point is 0x60 (PUSHAL instruction)
                    if (_fileBytes[entryPointOffset] == 0x60) {
                        // Write a bad detection message
                        ColoredConsole.WriteBadDetection("PUSHAL_AT_ENTRY", "Strange entry point");
                        badDetected = true;
                    }
                }
            }
        }


        /// <summary>
        /// Checks if the DOS stub of a file contains any custom DOS stubs.
        /// </summary>
        private void CheckCustomDosStub() {
            // List of custom DOS stubs to check for
            string[] customDosStubs = {
                "This program cannot be run in DOS mode.",
                "This program must be run under Win32",
                "This program must be run under Win64",
                "This program requires Win32"
            };

            // Get the DOS stub bytes from the file
            byte[] dosStubBytes = _fileBytes.Take(350).ToArray();

            // Convert the DOS stub bytes to a string
            string dosStubString = Encoding.ASCII.GetString(dosStubBytes);

            // Check if the DOS stub contains any of the custom DOS stubs
            foreach (string customDosStub in customDosStubs) {
                if (dosStubString.Contains(customDosStub)) {
                    return; // If a custom DOS stub is found, exit the method
                }
            }

            // If no custom DOS stub is found, write a bad detection message
            ColoredConsole.WriteBadDetection("CUSTOM_DOS_STUB", "The assembly uses an unusual DOS Stub");
            badDetected = true;
        }


        /// <summary>
        /// This method checks if the import table exists in the PE file.
        /// If the import table is missing, it logs a warning message.
        /// </summary>
        private void CheckImports() {
            // Check if the imported functions are not null
            if (_peFile.ImportedFunctions != null) {
                try {
                    // Attempt to check if there are any imported functions
                    _peFile.ImportedFunctions.Any();
                } catch (Exception) {
                    // If an exception is caught, it means that the import table is missing
                    // Log a warning message using ColoredConsole
                    ColoredConsole.WriteBadDetection("IMPORT_TABLE_MISSING", "There is no import table in the file");
                    badDetected = true;
                }
            }
        }


        /// <summary>
        /// This method checks the sections of a PE (Portable Executable) file for known packer signatures.
        /// </summary>
        private void CheckSections() {
            // Flag to track if any packer signatures are detected in the sections
            bool sectionsDetected = false;

            // Check if the PE file has any image sections
            if (_peFile.ImageSectionHeaders != null) {
                // Iterate over each section in the PE file
                foreach (var section in _peFile.ImageSectionHeaders) {
                    // Iterate over each known packer signature
                    foreach (var (detectedPacker, detectedVersion, sectionName) in KnownSections) {
                        // Check if the current section matches the known packer signature
                        if (!sectionsDetected && section.Name == sectionName) {
                            // Write a warning message for the detected packer
                            ColoredConsole.WriteBadDetection($"SECTIONS_LIKE_{detectedPacker.ToUpper()
                                .Replace(" ", "_")
                                .Replace("-", "")
                                .Replace(".", "")}", "Section like " + detectedPacker + (detectedVersion != String.Empty ? "v" + detectedVersion : ""));

                            sectionsDetected = true;
                        }
                    }
                }
            }
        }
    }
}
