/*
 ***********************************************************************************************************************
 * File: scanner.hpp
 * Description: This header file contains declarations of constants, classes and their associated member functions
 * that are to be used as part of scanning module.
 * Author: 0x6D76
 * Copyright (c) 2023 0x6D76 (0x6D76@proton.me)
 ***********************************************************************************************************************
 */

#ifndef PORTHAWK_SCANNER_HPP
#define PORTHAWK_SCANNER_HPP
#include <thread>
#include <vector>
#include "logger.hpp"
#include "pugixml.hpp"
#include "utilities.hpp"
/* Constants Declarations */
const int MAX_THREADS               = 20;
const std::string STATE_OPEN        = "open";
const std::string STATE_FILTERED    = "filtered";
const std::string BASE_NMAP_OPEN    = "nmap -Pn -T4 --min-rate=2000 -p- -oX " + XML_OPEN;
const std::string XML_SRV_CONFIG    = DIR_CWD + "services.xml";
/* Port class*/
class Port {
public:
    std::string portid;
    std::string state;
    std::string service;
    std::string product;
    std::string version;
    std::vector <std::string> vulns;
    /* Member functions */
    Port (const std::string &id, const std::string &status, const std::string &name = "N/A");
};
/* PortHawkScanner class */
class PortHawkScanner {
private:
    std::string address;
    int numOpen;
    int numFilter;
    std::vector <std::string> portsOpen;
    std::vector <std::string> portsFilter;
    std::map <std::string, std::unique_ptr <Port>> mapPort;
    std::mutex mutexXmlAccess;
public:
    explicit PortHawkScanner (const std::string &target);
    int GetOpenPorts ();
    void SummaryOpenPorts ();
    int MultiThreadedServicesProbe (int maxThreads = MAX_THREADS);
};
#endif /* PORTHAWK_SCANNER_HPP */
