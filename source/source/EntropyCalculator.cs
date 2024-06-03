namespace PE_LiteScan {
    /// <summary>
    /// Contains methods for calculating the entropy of a byte array.
    /// </summary>
    public static class EntropyCalculator {
        /// <summary>
        /// Calculates the entropy of a byte array.
        /// </summary>
        /// <param name="data">The byte array to calculate the entropy for.</param>
        /// <returns>The entropy of the byte array.</returns>
        public static double Calc(byte[] data) {
            // Count the occurrences of each byte value in the data array
            int[] counts = new int[256];
            foreach (byte b in data) {
                counts[b]++;
            }

            double entropy = 0.0;
            int dataSize = data.Length;
            // Calculate the entropy for each byte value
            for (int i = 0; i < 256; i++) {
                // Skip byte values that have not been encountered in the data array
                if (counts[i] == 0) continue;
                double p = (double)counts[i] / dataSize;
                // Calculate the entropy for the current byte value
                entropy -= p * Math.Log(p, 2);
            }

            return entropy;
        }
    }
}
