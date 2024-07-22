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

#include <mutex>
#include <thread>
#include "logger.hpp"
#include "pugixml.hpp"
#include "utilities.hpp"

const int MAX_THREADS = 20;
const std::string STATE_OPEN = "open";
const std::string STATE_FLTR = "filtered";
const std::string STATE_CLSD = "closed";

const std::string BASE_NMAP_OPEN = "nmap -Pn -T4 -sT --min-rate=2000 -p- -oX $xmlFile $target";
const std::string BASE_NMAP_DEEP = "nmap -sT -sV -sC --script=vuln -p $id -oX $xmlFile $target";

/* Port class */
class Port {
    public:
        std::string portid;
        std::string state;
        std::string service;
        std::string product;
        std::string version;
        std::string osName;
        std::vector <std::string> vulnerabilities;
        std::vector <std::string> scansCompleted;
        std::vector <std::string> scansFailed;

        /* Member functions */
        Port (const std::string &id, const std::string &status, const std::string &name = "N/A");
        int DeepServiceProbe (const std::string &address, Logger masterLog);

}; /* End of class Port */

/* Host class */
class Host {
    private:
        std::string address;
        int numOpen;
        int numFilter;
        std::vector <Port> openPorts;
        std::vector <Port> filterPorts;
        std::mutex mtx;
    public:
        Host (const std::string &addr);
        void AddPortToHost (const Port &port);
        ReturnCodes GetOpenPorts (Logger objLog);
        void PrintOpenScanSummary (Logger objLog);
        int MultitreadedServiceProbe (Logger objLog, int maxThreads = MAX_THREADS);

}; /* End of class Host */

#endif