/*
 ***********************************************************************************************************************
 * File: utilities.hpp
 * Description: This file contains declarations of commonly used constants and functions that are to be used across
 * the tool or otherwise unclassifiable.
 * Author: 0x6D76
 * Copyright (c) 2023 0x6D76 (0x6D76@proton.me)
 ***********************************************************************************************************************
 */

#ifndef PORTHAWK_UTILITIES_HPP
#define PORTHAWK_UTILITIES_HPP
#include <arpa/inet.h>
#include <cstdlib>
#include <netdb.h>
#include "logger.hpp"
/* Functions Declarations */
int PortHawk (int argCount, char **values);
int ConvertToIPAddress (const std::string &target, std::string &address);
int ValidateArguments (int argCount, char **values, std::string &address);
int InitializeTool (int argCount, char **values, std::string &address);
int ExecuteSystemCommand (const std::string &command, std::stringstream &output);
#endif /* PORTHAWK_UTILITIES_HPP */
