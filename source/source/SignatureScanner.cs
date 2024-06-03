namespace PE_LiteScan {
    /// <summary>
    /// This class is responsible for scanning a byte array for the presence of a given signature.
    /// </summary>
    public class SignatureScanner {
        private readonly byte[] _fileBytes;

        /// <summary>
        /// Initializes a new instance of the <see cref="SignatureScanner"/> class.
        /// </summary>
        /// <param name="fileBytes">The byte array to scan.</param>
        public SignatureScanner(byte[] fileBytes) {
            _fileBytes = fileBytes;
        }

        /// <summary>
        /// Checks if the given signature is present in the file bytes.
        /// </summary>
        /// <param name="signature">The signature to search for. Format: "byte1 byte2 ..." where byte can be a hexadecimal byte or a string enclosed in single quotes.</param>
        /// <returns>True if the signature is found, false otherwise.</returns>
        public bool ContainsSignature(string signature) {
            // Split the signature into individual parts
            string[] signatureParts = signature.Split(' ');

            List<byte> signatureBytes = new List<byte>();
            List<bool> isWildcard = new List<bool>();

            foreach (string part in signatureParts) {
                if (part.StartsWith("'") && part.EndsWith("'")) { // If the part is a string, convert each character to a byte and add it to the signature bytes
                    string stringValue = part.Substring(1, part.Length - 2);
                    foreach (char c in stringValue) {
                        signatureBytes.Add((byte)c);
                        isWildcard.Add(false);
                    }
                } else if (part == "??" || part == "..") {
                    // Unknown byte
                    signatureBytes.Add(0x00); // Add a placeholder byte
                    isWildcard.Add(true); // Mark as wildcard
                } else {
                    // If the part is a hexadecimal byte, parse it and add it to the signature bytes
                    signatureBytes.Add(Convert.ToByte(part, 16));
                    isWildcard.Add(false);
                }
            }

            // Convert the signature bytes to an array and check if the file bytes contain the signature
            byte[] signatureBytesArray = signatureBytes.ToArray();
            bool[] isWildcardArray = isWildcard.ToArray();

            return ContainsSequence(_fileBytes, signatureBytesArray, isWildcardArray);
        }

        /// <summary>
        /// Checks if a byte array contains a specific sequence of bytes.
        /// </summary>
        /// <param name="source">The byte array to search in.</param>
        /// <param name="sequence">The sequence of bytes to search for.</param>
        /// <param name="isWildcard">Array indicating which bytes in the sequence are wildcards.</param>
        /// <returns>True if the sequence is found, false otherwise.</returns>
        private bool ContainsSequence(byte[] source, byte[] sequence, bool[] isWildcard) {
            // Calculate the length of the sequence and the limit of the search
            int seqLength = sequence.Length;
            int limit = source.Length - seqLength + 1;

            // Iterate through the source array
            for (int i = 0; i < limit; i++) {
                bool found = true;

                // Iterate through the sequence array
                for (int j = 0; j < seqLength; j++) {
                    // If the current byte in the sequence is not a wildcard and it doesn't match the corresponding byte in the source, the sequence is not found
                    if (!isWildcard[j] && source[i + j] != sequence[j]) {
                        found = false;
                        break;
                    }
                }

                // If the sequence is found, return true
                if (found) return true;
            }

            // If the sequence is not found after searching the entire source array, return false
            return false;
        }
    }
}
