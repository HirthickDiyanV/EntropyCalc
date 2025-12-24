#include <stdio.h>
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>

/**
 * detect_encryption - Detects high entropy using Integer Chi-Square
 * @buffer: 4096 byte input
 * @len: length of buffer (optimized for 4096)
 * * Returns 1 if data is likely encrypted/compressed (High Entropy)
 * Returns 0 if data is likely structured (Low Entropy)
 */
int detect_encryption(unsigned char *buffer, int len) {
    uint32_t counts[256] = {0};
    uint32_t chi_sq_sum = 0;
    
    // 1. Frequency count
    for (int i = 0; i < len; i++) {
        counts[buffer[i]]++;
    }

    // 2. Calculate sum of (Observed - Expected)^2
    // For 4096 bytes, Expected (E) is exactly 16 per bucket.
    for (int i = 0; i < 256; i++) {
        int32_t diff = (int32_t)counts[i] - 16;
        chi_sq_sum += (diff * diff);
    }

    /* * Thresholding:
     * In a 4096-byte sample, a perfectly random source results in a 
     * chi_sq_sum of ~4080 (which corresponds to a standard Chi-Square score 
     * of 255 after dividing by E=16).
     * * Structured data (text, code, headers) will have a much higher sum 
     * because the byte distribution is uneven.
     * Threshold: If chi_sq_sum is LOW, it is high entropy (random).
     */
    if (chi_sq_sum < 10000) {
        return 1; // High Entropy / Likely Encrypted
    }
    
    return 0; // Structured / Safe
}

// --- Test Main ---

void test_file(const char *filename) {
    unsigned char buffer[4096];
    int fd = open(filename, O_RDONLY);
    if (fd < 0) {
        printf("File %s not found. Skipping...\n", filename);
        return;
    }

    ssize_t bytes_read = read(fd, buffer, 4096);
    close(fd);

    if (bytes_read < 4096) {
        printf("File %s too small for 4KB test.\n", filename);
        return;
    }

    int result = detect_encryption(buffer, 4096);
    printf("File: %-20s | Result: %s\n", filename, 
           result ? "[!] HIGH ENTROPY (Encrypted)" : "[+] STRUCTURED (Safe)");
}

int main() {
    printf("Running Entropy Detection Test...\n");
    printf("--------------------------------------------------\n");

    // Before running, ensure these files exist:
    // 1. base_text.txt (Just a text file > 4KB)
    // 2. sample_image.jpg (A standard JPEG)
    // 3. encrypted.bin (Generated via: openssl enc -aes-256-cbc -salt -in base_text.txt -out encrypted.bin -k password)
    
    test_file("base_text.txt");
    test_file("sample_image.jpg");
    test_file("encrypted.bin");

    return 0;
}
