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
#include "scanner.hpp"
#include "utilities.hpp"

std::string LOG_DIR;
std::string MASTER_LOG;

int main (int argCount, char **values) {
    
    std::signal (SIGINT, KeyboardInterrupt);
    std::string target;
    std::string rawFile = LOG_RAW;
    Logger rawLog (rawFile);
    if (ValidateArguments (argCount, values, target) == TARGET_ADDR_PASS) {
        rawLog.Header (target, false);
        class Host host (target);
        host.GetOpenPorts (rawLog);
        host.PrintOpenScanSummary (rawLog);
        host.MultitreadedNMAPScript (rawLog);
        host.PrintDeepScanSummary (rawLog);
    }
    rawLog.Footer (false);
    return 0;
} /* End of main () */