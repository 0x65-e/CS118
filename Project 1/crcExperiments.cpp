#include <algorithm>
#include <bitset>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <unistd.h>

/**
 * @brief Ensures that a C-style null terminated string contains only the characters '1' and '0'.
 * 
 * @param bitstring C-style null terminated string
 * @return true if valid, false if any other character is detected.
 */
bool validateBitstring(char* bitstring) {
    while (*bitstring != 0) {
        if (*bitstring != '1' && *bitstring != '0') return false;
        bitstring++;
    }
    return true;
}

/**
 * @brief Generates a CRC-16 for the provided message.
 * 
 * @param message string composed of only '1' and '0' characters.
 * @param generator the lower 16 bits of the 17-bit CRC generator. The MSB (x^16) is assumed to be one.
 * @return the message concatenated with the calculated CRC (at the highest 16 positions).
 */
std::string generateCRC16(std::string message, uint16_t generator) {
    size_t rounds = message.size();
    std::bitset<16> G(generator);
    std::bitset<16> M(message);
    if (message.length() < 16) M <<= 16 - message.length();
    
    for (size_t i = 0; i < rounds; i++) {
        bool divideBy = M[15];
        M <<= 1;
        if (rounds - i > 16) M.set(0, message[16 + i] == '1');
        //std::cout << "Message: " << M << std::endl;
        if (divideBy) M ^= G;
    }
    message.append(M.to_string());
    return message;
}

/**
 * @brief Checks if the string `bitstring` has a valid CRC16 using `generator`.
 * Passing a `bitstring` of less than length 17 results in a panic.
 * 
 * @param bitstring string composed of only '1' and '0' characters of at least length 17
 * @param generator the lower 16 bits of the 17-bit CRC generator. The MSB (x^16) is assumed to be one.
 * @return 1 if the CRC16 is valid, 0 if invalid
 */
int validateCRC16(const std::string& bitstring, uint16_t generator) {
    if (bitstring.length() <= 16) {
        std::cout << "Message length must be at least 17 bits. Quitting..." << std::endl;
        exit(1);
    }
    // Generate the "right" CRC for the message and string compare with the provided bitstring
    return !(generateCRC16(bitstring.substr(0, bitstring.length() - 16), generator).compare(bitstring));
}

/**
 * @brief Adds an error term via XOR to a provided bitstring. The two parameters must be the same length.
 * 
 * @param bitstring string composed of only '1' and '0' characters.
 * @param error string composed of only '1' and '0' characters of the same length as `bitstring`.
 * @return `bitstring` ^ `error`.
 */
std::string addErrorTerm(std::string bitstring, const std::string& error) {
    if (bitstring.length() != error.length()) {
        std::cout << "Error term incorrect length for message." << std::endl;
        return bitstring;
    }
    for (size_t i = 0; i != bitstring.length(); i++) {
        if (error.at(i) == '1') {
            if (bitstring[i] == '1') bitstring[i] = '0';
            else bitstring[i] = '1';
        }
    }
    return bitstring;
}

/**
 * @brief Counts (and potentially prints) the number of undetected errors of size `nerrors` possible in `bitstring`
 * with the provided `generator`.
 * 
 * @param bitstring string containing a binary message *with attached CRC-16*.
 * @param generator the lower 16 bits of the 17-bit CRC generator. The MSB (x^16) is assumed to be one.
 * @param nerrors number of bit flips in the error
 * @param print true to print every result found, false for silent mode
 * @return the number of errors found
 */
int countErrors(std::string bitstring, uint16_t generator, size_t nerrors, bool print) {
    std::bitset<16> G(generator);
    // An even-parity generator can never create an odd number of errors
    if (G.count() % 2 == 1 && nerrors % 2 == 1) return 0;

    int totalErrors = 0;
    size_t messageLength = bitstring.length();
    if (messageLength < nerrors) return 0;
    std::string error;
    error.reserve(messageLength);
    error.append(messageLength - nerrors, '0');
    error.append(nerrors, '1');
    do {
        std::string noisyMessage = addErrorTerm(bitstring, error);
        if (validateCRC16(noisyMessage, generator)) {
            totalErrors++;
            if (print) std::cout << noisyMessage << std::endl;
        }
    } while (std::next_permutation(error.begin(), error.end()));
    return totalErrors;
}

int main(int argc, char* argv[]) {
    int opt;

    while((opt = getopt(argc, argv, "c:v:f:t:p:")) != -1) {
        switch(opt) {
            case 'c':
                if (!validateBitstring(optarg)) {
                    std::cout << "Invalid character detected in bitstring. Quitting..." << std::endl;
                    return 1;
                }
                std::cout << generateCRC16(optarg, 0b0001000010100001) << std::endl;
                break;
            case 'v':
                if (!validateBitstring(optarg)) {
                    std::cout << "Invalid character detected in bitstring. Quitting..." << std::endl;
                    return 1;
                }
                std::cout << validateCRC16(optarg, 0b0001000010100001) << std::endl;
                break;
            case 'f':
                if (!validateBitstring(optarg)) {
                    std::cout << "Invalid character detected in bitstring. Quitting..." << std::endl;
                    return 1;
                }
                countErrors(generateCRC16(optarg, 0b1001000000000101), 0b1001000000000101, 4, true);
                break;
            case 't':
                if (!validateBitstring(optarg)) {
                    std::cout << "Invalid character detected in bitstring. Quitting..." << std::endl;
                    return 1;
                }
                std::cout << countErrors(generateCRC16(optarg, 0b1001000000000101), 0b1001000000000101, 5, false) << std::endl;
                break;
            case 'p':
                if (!validateBitstring(optarg)) {
                    std::cout << "Invalid character detected in bitstring. Quitting..." << std::endl;
                    return 1;
                }
                std::cout << countErrors(generateCRC16(optarg, 0b1000000000000101), 0b1000000000000101, 5, false) << std::endl;
                break;
        }
    }
}
