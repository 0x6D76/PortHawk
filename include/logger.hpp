/*
 ***********************************************************************************************************************
 * File: logger.hpp
 * Description: This header file contains declarations of constants, support functions, classes and member functions
 * associated with logging functionalities
 * Author: 0x6D76
 * Copyright (c) 2023 0x6D76 (0x6D76@proton.me)
 ***********************************************************************************************************************
 */

#ifndef PORTHAWK_LOGGER_HPP
#define PORTHAWK_LOGGER_HPP
#include <ctime>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <map>
#include <sstream>
#include <string>
/* Constant Declarations */
const int PASS  =  100;
const int INFO  =  0;
const int FAIL  = -100;
const int HEAD  =  50;
const int FOOT  = -50;
const int WIDTH =  120;
const std::string UNKNOWN   = "Ran into an unknown error.";
const std::string TOOL      = "PortHawk";
const std::string VERSION   = "0.1a";
const std::string HEADER    = TOOL + VERSION;
const std::string FOOTER    = "Exiting the tool";
const std::string LINE      = "========================================================================================"
                              "================================";
const std::string HALF_LINE = "============================================================";
/* Color codes */
const std::string RST = "\x1B[0m";
const std::string RED = "\x1B[31m";
const std::string GRN = "\x1B[32m";
const std::string YEL = "\x1B[33m";
const std::string BLU = "\x1B[34m";
const std::string MAG = "\x1B[35m";
const std::string CYN = "\x1B[36m";
/* Modules Names */
const std::string MOD_INIT          = "Initialization";
const std::string MOD_OPEN          = "Open Ports scanning";
const std::string MOD_XML_OPEN      = "XML Open Ports scanning";
const std::string MOD_PORTS_SUM     = "Ports Summary";
const std::string MOD_MULTI_SCAN    = "Multi-threaded deep services probe";
const std::string MOD_DEEP_SRV_SCAN = "Deep Service Probe";
/* Directories & Logs */
const std::string DIR_CWD   = std::filesystem::absolute("");
const std::string DIR_LOGS  = DIR_CWD + "Logs/";
const std::string LOG_RAW   = DIR_LOGS + "PH_raw.log";
const std::string XML_OPEN  = DIR_LOGS + "open_ports.xml";
const std::string DIR_PORTS = DIR_LOGS + "Ports_Scan/";
/* Return Codes */
enum ReturnCodes {
    OPEN_FOUND_FAIL = -9,
    FILTER_FOUND_FAIL = -8,
    PORTS_FOUND_FAIL = -7,
    XML_OPEN_FAIL = -6,
    NMAP_OPEN_FAIL = -5,
    CMD_EXEC_FAIL = -4,
    DIR_CREATE_FAIL = -3,
    TARGET_ADDR_FAIL = -2,
    ARG_NUM_FAIL = -1,
    ARG_NUM_PASS = 1,
    TARGET_ADDR_PASS = 2,
    DIR_CREATE_PASS = 3,
    CMD_EXEC_PASS = 4,
    NMAP_OPEN_PASS = 5,
    XML_OPEN_PASS = 6,
    PORTS_FOUND_PASS = 7,
    FILTER_FOUND_PASS = 8,
    OPEN_FOUND_PASS = 9,
    MULTI_THREAD_PROBE_INFO = 10,
};
/* Return Messages */
static std::map <ReturnCodes, std::string> ReturnMessages = {
        {OPEN_FOUND_FAIL, "No open port found on the target. Check raw log for more details. Exiting tool."},
        {FILTER_FOUND_FAIL, "No filtered port found on the target."},
        {PORTS_FOUND_FAIL, "No usable ports found on the target. Check scan results on raw log for more details."},
        {XML_OPEN_FAIL, "Parsing open ports xml file has failed."},
        {NMAP_OPEN_FAIL, "Executing NMAP open ports scan has failed. Check raw log for more details"},
        {CMD_EXEC_FAIL, "Executing system command has failed."},
        {DIR_CREATE_FAIL, "Creating directories has failed. Check raw log for error details."},
        {TARGET_ADDR_FAIL, "Target is invalid. Check input and try again."},
        {ARG_NUM_FAIL, "Argument(s) mismatch. Check input and try again."},
        {ARG_NUM_PASS, "Argument(s) counts has been validated."},
        {TARGET_ADDR_PASS, "Target address is validated."},
        {DIR_CREATE_PASS, "Directories have been created."},
        {CMD_EXEC_PASS, "System command has been executed."},
        {NMAP_OPEN_PASS, "NMAP Open ports scan has been completed."},
        {XML_OPEN_PASS, "Parsing open ports xml has been completed."},
        {PORTS_FOUND_PASS, "Identified usable ports on the target."},
        {FILTER_FOUND_PASS, "Identified filtered port(s) on the target."},
        {OPEN_FOUND_PASS, "Identified open port(s) on the target."},
        {MULTI_THREAD_PROBE_INFO, "Initiated multi-threaded service probe on all open port(s)."},
};
/* Logger class */
class Logger {
private:
    int severity;
    int retCode;
    bool verbose;
    std::ofstream fileRaw;
    std::string nameLog;
    std::string message;
    std::string module;
    std::stringstream optional;
public:
    explicit Logger (int type);
    Logger (int type, const std::string &nameModule, int code, const std::string &nameFile, bool output = false,
            const std::stringstream &opt = std::stringstream ());
    void PrintToolLabel ();
    void FormatLog (std::stringstream &strVerbose, std::stringstream &strFile);
    void LogMessage ();
    void ExitExecution ();
};
/* Function Declaration */
std::string GetReturnMessage (ReturnCodes returnCode);
std::string GetCurrentTime ();
#endif /* PORTHAWK_LOGGER_HPP */
