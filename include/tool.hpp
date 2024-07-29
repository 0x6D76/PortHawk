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
const std::string MOD_MULTI_SCAN = "Multi-threaded NMAP Script Scan";
const std::string MOD_DEEP_SCAN = "NMAP Script Scan";
const std::string MOD_DEEP_SUM = "NMAP Script Scan Summary";

/* Return Codes */
/* Use postive integers for PASS and INFO messages and negative integers for FAIL messages. */
enum ReturnCodes {
    VULNS_NOT_FOUND = -17,
    ANTI_INFO_NMAP_SCRIPT_SUM = -16,
    NMAP_SCRIPT_FAIL = -15,
    NMAP_SCRIPT_XML_FAIL = -14,
    NMAP_SCRIPT_EXEC_FAIL = -13,
    ANTI_INFO_NMAP_SCRIPT = -12,
    MT_NMAP_SCRIPT_FAIL = -11,
    ANTI_INFO_MT_NMAP_SCRIPT = -10,
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
    MT_NMAP_SCRIPT_INFO = 10,
    MT_NMAP_SCRIPT_PASS = 11,
    NMAP_SCRIPT_INFO = 12,
    NMAP_SCRIPT_EXEC_PASS = 13,
    NMAP_SCRIPT_XML_PASS = 14,
    NMAP_SCRIPT_PASS = 15,
    NMAP_SCRIPT_SUM_INFO = 16,
    VULNS_FOUND = 17,
};

/* Return Messages */
/* Make sure to leave a space after the message, to make adding optional messages presentable. */
static std::map <ReturnCodes, std::string> ReturnMessages = {
    {VULNS_NOT_FOUND, "No known vulnerabilities found, as per NMAP vulnerability scan. "},
    {NMAP_SCRIPT_FAIL, "Probing port for deeper information has failed. "},
    {NMAP_SCRIPT_XML_FAIL, "Parsing the XML file to identify deep information has failed. " },
    {NMAP_SCRIPT_EXEC_FAIL, "Executing NMAP script scan on port has failed. "},
    {MT_NMAP_SCRIPT_FAIL, "Running multithreaded NMAP script scan against open ports has failed. "},
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
    {MT_NMAP_SCRIPT_INFO, "Initiated multi-threaded NMAP script scan on all identified open port(s). "},
    {MT_NMAP_SCRIPT_PASS, "Running multithreaded NMAP script scan against open ports has been completed. "},
    {NMAP_SCRIPT_INFO, "Initiated NMAP script scan against the target. "},
    {NMAP_SCRIPT_EXEC_PASS, "NMAP script scan on target has been completed. "},
    {NMAP_SCRIPT_XML_PASS, "NMAP script scan xml file has been parsed successfully. "},
    {NMAP_SCRIPT_PASS, "NMAP script scan has been completed successfully. "},
    {NMAP_SCRIPT_SUM_INFO, "NMAP Script Scan Summary. "},
    {VULNS_FOUND, "Possible known vulnerability found on the port. "},
};

#endif