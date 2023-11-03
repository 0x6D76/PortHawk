/*
 ***********************************************************************************************************************
 * File: porthawk.cpp
 * Description: This file contains the definition of PortHawk function, that kicks off and manages the execution of
 * the tool.
 * Functions: int PortHawk ()
 * Author: 0x6D76
 * Copyright (c) 2023 0x6D76 (0x6D76@proton.me)
 ***********************************************************************************************************************
 */

#include "logger.hpp"
#include "utilities.hpp"

int PortHawk (int argCount, char **values) {

    std::string address;
    int retCode = InitializeTool (argCount, values, address);
    Logger (PASS, MOD_INIT, retCode, LOG_RAW, true).LogMessage ();

    Logger (FOOT).PrintToolLabel ();
    return 0;
} /* End of PortHawk () */