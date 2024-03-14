#include <iostream>
#include <random>

int main() {
    // Create a random number engine
    std::random_device rd;
    std::mt19937 gen(rd()); // Mersenne Twister pseudo-random number generator

    // Define a distribution
    int lowerBound = 1;
    int upperBound = 100;
    std::uniform_int_distribution<int> dist(lowerBound, upperBound);

    // Generate random numbers
    //int randomValue = dist(gen);
    for (int i = 0; i < 10; i++){
        std::cout << "Random value between " << lowerBound << " and " << upperBound << ": " << dist(gen) << std::endl;
    }
    

    return 0;
}