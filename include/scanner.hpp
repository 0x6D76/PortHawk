/*
 ***********************************************************************************************************************
 * File: scanner.hpp
 * Description: This file contains declarations of constants, support functions, classes its member functions & 
 *              support functions associated with scanning functionalities.
 *
 * Author: 0x6D76
 * Copyright (c) 2024 0x6D76 (0x6D76@proton.me)
 ***********************************************************************************************************************
 */
#ifndef PORTHAWK_SCANNER_HPP
#define PORTHAWK_SCANNER_HPP

#include "logger.hpp"
#include "pugixml.hpp"
#include "utilities.hpp"

const std::string STATE_OPEN = "open";
const std::string STATE_FLTR = "filtered";
const std::string STATE_CLSD = "closed";

/* Port class */
class Port {
    public:
        std::string portid;
        std::string state;
        std::string service;
        std::string product;
        std::string version;
        std::vector <std::string> vulnerabilities;
        std::vector <std::string> scansCompleted;
        std::vector <std::string> scansFailed;

        /* Member functions */
        Port (const std::string &id, const std::string &status, const std::string &name = "N/A");

}; /* End of class Port */

/* Host class */
class Host {
    private:
        std::string address;
        int numOpen;
        int numFilter;
        std::vector <Port> openPorts;
        std::vector <Port> filterPorts;
    public:
        Host (const std::string &addr);
        void AddPortToHost (const Port &port);
        ReturnCodes GetOpenPorts (Logger objLog);
        void PrintOpenScanSummary (Logger objLog);

}; /* End of class Host */

#endif