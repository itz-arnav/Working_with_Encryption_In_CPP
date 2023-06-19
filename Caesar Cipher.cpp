#include <iostream>
#include <string>

std::string encryptCaesarCipher(std::string text, int s) {
    std::string result = "";

    // traverse text
    for (int i=0;i<text.length();i++) {
        // apply transformation to each character
        // Encrypt uppercase characters
        if (isupper(text[i]))
            result += char(int(text[i]+s-65)%26 +65);

            // Encrypt lowercase characters
        else
            result += char(int(text[i]+s-97)%26 +97);
    }

    // Return resulting string
    return result;
}

int main() {
    std::string text="ATTACKATONCE";
    int s = 4;
    std::cout << "Text  : " << text;
    std::cout << "\nShift : " << s;
    std::cout << "\nCipher: " << encryptCaesarCipher(text, s);
    return 0;
}