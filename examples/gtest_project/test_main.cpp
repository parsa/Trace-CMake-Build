#include <gtest/gtest.h>

int factorial(int n) {
    return (n <= 1) ? 1 : n * factorial(n - 1);
}

TEST(FactorialTest, HandlesZero) {
    EXPECT_EQ(factorial(0), 1);
}

TEST(FactorialTest, HandlesPositive) {
    EXPECT_EQ(factorial(1), 1);
    EXPECT_EQ(factorial(5), 120);
    EXPECT_EQ(factorial(10), 3628800);
}

