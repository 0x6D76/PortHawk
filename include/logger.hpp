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
const std::string MOD_INIT      = "Initialization";
/* Directories & Logs */
const std::string DIR_CWD   = std::filesystem::absolute("");
const std::string DIR_LOGS  = DIR_CWD + "Logs/";
const std::string LOG_RAW   = DIR_LOGS + "PH_raw.log";
const std::string XML_OPEN  = DIR_LOGS + "open_ports.xml";
const std::string DIR_PORTS = DIR_LOGS + "Ports_Scan/";
/* Return Codes */
enum ReturnCodes {
    ARG_NUM_FAIL = -1,
    ARG_NUM_PASS = 1
};
/* Return Messages */
static std::map <ReturnCodes, std::string> ReturnMessages = {
        {ARG_NUM_FAIL, "Argument(s) mismatch. Check input and try again."},
        {ARG_NUM_PASS, "Argument(s) counts has been validated."}
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
