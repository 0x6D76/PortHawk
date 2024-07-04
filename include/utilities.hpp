/*
 ***********************************************************************************************************************
 * File: utilities.hpp
 * Description: This file contains declarations of commonly used constants & functions that are to be used across the
 *              tool or otherwise unclassifiable.
 * 
 * Author: 0x6D76
 * Copyright (c) 2024 0x6D76 (0x6D76@proton.me)
 ***********************************************************************************************************************
 */

#ifndef PORTHAWK_UTILITIES_HPP
#define PORTHAWK_UTILITIES_HPP
#include <arpa/inet.h>
#include <csignal>
#include <netdb.h>
#include "logger.hpp"

//volatile sig_atomic_t keepRunning = 1;

/* Function Declarations */
void UsageExit (ReturnCodes code);
void KeyboardInterrupt (int signal);
ReturnCodes ExecuteSystemCommand (const std::string &command, std::stringstream &output);
ReturnCodes ValidateArguments (int argCount, char **values, std::string &address);
ReturnCodes ConvertToIPAddress (const std::string &target, std::string &address);

#endif