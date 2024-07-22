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
const std::string MOD_NMAP_OPEN = "Open Ports Scanning";
const std::string MOD_XML_OPEN = "Open Ports XML Parsing";
const std::string MOD_SUM_PORTS = "Ports Summary";
const std::string MOD_MULTI_SCAN = "Multi-threaded Deep Services Scan";
const std::string MOD_DEEP_SCAN = "Deep Service Probe";

/* Return Codes */
/* Use postive integers for PASS and INFO messages and negative integers for FAIL messages. */
enum ReturnCodes {
    DEEP_SERVICE_XML_FAIL = -14,
    DEEP_SERVICE_FAIL = -13,
    ANTI_INFO_DEEP_SERVICE = -12,
    MULTI_THREAD_PROBE_FAIL = -11,
    ANTI_INFO_MULTI_THREAD = -10,
    OPEN_FOUND_FAIL = -9,
    FILTER_FOUND_FAIL = -8,
    PORT_FOUND_FAIL = -7,
    OPEN_XML_FAIL = -6,
    OPEN_NMAP_FAIL = -5,
    TARGET_ADDR_FAIL = -4,
    ARG_COUNT_FAIL = -3,
    CMD_EXEC_FAIL = -2,
    KEYBOARD_INT =  -1,
    KEYBOARD_NONE = 1,
    CMD_EXEC_PASS = 2,
    ARG_COUNT_PASS = 3,
    TARGET_ADDR_PASS = 4,
    OPEN_NMAP_PASS = 5,
    OPEN_XML_PASS = 6,
    PORTS_FOUND_PASS = 7,
    FILTER_FOUND_PASS = 8,
    OPEN_FOUND_PASS = 9,
    MULTI_THREAD_PROBE_INFO = 10,
    MULTI_THREAD_PROBE_PASS = 11,
    DEEP_SERVICE_INFO = 12,
    DEEP_SERVICE_PASS = 13,
    DEEP_SERVICE_XML_PASS = 14,
};

/* Return Messages */
/* Make sure to leave a space after the message, to make adding optional messages presentable. */
static std::map <ReturnCodes, std::string> ReturnMessages = {
    {DEEP_SERVICE_XML_FAIL, "Parsing the XML file to identify deep information has failed. " },
    {DEEP_SERVICE_FAIL, "Executing NMAP deep probe on port has failed. "},
    {MULTI_THREAD_PROBE_FAIL, "Running multithreaded probe against open ports has failed. "},
    {OPEN_FOUND_FAIL, "No open port identied on the target. "},
    {FILTER_FOUND_FAIL, "No filtered port identified on the target. "},
    {PORT_FOUND_FAIL, "No port identified on the target. "},
    {OPEN_XML_FAIL, "Parsing the XML file to identify open ports has failed. "},
    {OPEN_NMAP_FAIL, "Executing NMAP scan for open ports has failed. "},
    {TARGET_ADDR_FAIL, "Given target address is an invalid one. "},
    {ARG_COUNT_FAIL, "Invalid number of args given. Check and try again. "},
    {CMD_EXEC_FAIL, "Executing the command has failed. "},
    {KEYBOARD_INT, "Keyboard interupt received. Quitting the tool. "},
    {CMD_EXEC_PASS, "Command has been successfully executed. "},
    {ARG_COUNT_PASS, "Correct number of args given. "},
    {TARGET_ADDR_PASS, "Target address has been validated. "},
    {OPEN_NMAP_PASS, "NMAP Open Ports scan has been completed. "},
    {OPEN_XML_PASS, "Open ports XML file has been parsed successfully. "},
    {PORTS_FOUND_PASS, "Port(s) identified on the target. "},
    {FILTER_FOUND_PASS, "Filtered port(s) identified on the target. "},
    {OPEN_FOUND_PASS, "Open port(s) identified on the target. "},
    {MULTI_THREAD_PROBE_INFO, "Initiated multi-threaded service probe on all identified open port(s). "},
    {MULTI_THREAD_PROBE_PASS, "Running multithreaded probe against open ports has been completed. "},
    {DEEP_SERVICE_INFO, "Initiated deep service NMAP probe in the target. "},
    {DEEP_SERVICE_PASS, "NMAP deep service probe on target has been completed. "},
    {DEEP_SERVICE_XML_PASS, "Deep probe xml file has been parsed successfully. "},
};

#endif