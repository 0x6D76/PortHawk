/*
 ***********************************************************************************************************************
 * File: tool.hpp
 * Description: This file contains macros, enums and other data structures associated with customizing tool information.
 * 
 * Author: 0x6D76
 * Copyright (c) 2024 0x6D76 (0x6D76@proton.me)
 ***********************************************************************************************************************
 */
#ifndef CPPLOGGER_TOOL_HPP
#define CPPLOGGER_TOOL_HPP
#include <map>
#include <string>
/*
 * Edit the following, on a per-tool basis to best match requirements.
 */

/* Tool Header */
const std::string TOOL = "Port Hawk";
const std::string VER  = "1.0";

/* Modules */
/* Naming convention is that the module names begin with 'MOD_'. */
const std::string MOD_SPL = "Special";
const std::string MOD_INIT = "Initialization";
const std::string MOD_CLEAN = "Clean-up";

/* Return Codes */
/* Use postive integers for PASS and INFO messages and negative integers for FAIL messages. */
enum ReturnCodes {
    TARGET_ADDR_FAIL = -4,
    ARG_COUNT_FAIL = -3,
    CMD_EXEC_FAIL = -2,
    KEYBOARD_INT =  -1,
    KEYBOARD_NONE = 1,
    CMD_EXEC_PASS = 2,
    ARG_COUNT_PASS = 3,
    TARGET_ADDR_PASS = 4,
};

/* Return Messages */
/* Make sure to leave a space after the message, to make adding optional messages presentable. */
static std::map <ReturnCodes, std::string> ReturnMessages = {
    {TARGET_ADDR_FAIL, "Given target address is a invalid one. "},
    {ARG_COUNT_FAIL, "Invalid number of args given. Check and try again. "},
    {CMD_EXEC_FAIL, "Executing the command has failed. "},
    {KEYBOARD_INT, "Keyboard interupt received. Quitting the tool. "},
    {CMD_EXEC_PASS, "Command has been successfully executed. "},
    {ARG_COUNT_PASS, "Correct number of args given. "},
    {TARGET_ADDR_PASS, "Target address has been validated. "},
};

#endif