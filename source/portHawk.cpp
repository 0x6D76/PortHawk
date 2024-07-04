/*
 ***********************************************************************************************************************
 * File: portHawk.cpp
 * Description:
 * Functions:
 * Author: 0x6D76
 * Copyright (c) 2024 0x6D76 (0x6D76@proton.me)
 ***********************************************************************************************************************
 */

#include "logger.hpp"
#include "utilities.hpp"

int main (int argCount, char **values) {
    std::signal (SIGINT, KeyboardInterrupt);

    std::string target;
    ValidateArguments (argCount, values, target);
    std::cout << target << std::endl;

    return 0;
}