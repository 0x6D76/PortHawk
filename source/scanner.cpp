/*
 ***********************************************************************************************************************
 * File: scanner.cpp
 * Description: This file contains various member functions of different classes that are to be used as part of the
 * scanner module.
 * Functions:
 *           Port
 *              Port ()
 *           PortHawkScanner
 *              PortHawkScanner ()
 *              GetOpenPorts ()
 * Author: 0x6D76
 * Copyright (c) 2023 0x6D76 (0x6D76@proton.me)
 ***********************************************************************************************************************
 */

#include "scanner.hpp"
/*
 * Constructor for a new Port object
 * :arg: id, const string holding the port number
 * :arg: status, const string holding the current state of the port
 * :arg: name, const string holding the name of the service running on the port
 */
Port::Port (const std::string &id, const std::string &status, const std::string &name) {

    portid = id;
    state = status;
    service = name;
    product = "";
    std::filesystem::create_directories (DIR_PORTS + portid);
} /* End of Port () */


/*
 * Constructor for new PortHawkScanner object
 * :arg: target, const string holding the validated IP address of the target
 */
PortHawkScanner::PortHawkScanner (const std::string &target) {

    address = target;
    numOpen = 0;
    numFilter = 0;
    portsOpen = {};
    portsFilter = {};
} /* End of PortHawkScanner () */


/*
 * This function executes NMAP open ports scan against the target and parses the XML file to identify ope and
 * filtered ports, along with their respective states, ids and service names.
 * :return: integer value denoting success or failure of the operation.
 */
int PortHawkScanner::GetOpenPorts () {

    std::string module {};
    /* Running NMAP open ports scanning */
    module = MOD_OPEN;
    std::stringstream command {};
    std::stringstream output {};
    command << BASE_NMAP_OPEN << " " << address;
    /* Exit execution if running NMAP scan has failed */
    if (ExecuteSystemCommand (command.str(), output) < 0) {
        Logger (FAIL, module, NMAP_OPEN_FAIL, LOG_RAW, true, output).ExitExecution ();
    }
    Logger (PASS, module, NMAP_OPEN_PASS, LOG_RAW, true, output).LogMessage ();
    /* Parsing NMAP scan results */
    module = MOD_XML_OPEN;
    pugi::xml_document document;
    if (!document.load_file (XML_OPEN.c_str ())) {
        Logger (FAIL, module, XML_OPEN_FAIL, LOG_RAW, true, output).ExitExecution ();
    }
    pugi::xml_node port;
    pugi::xml_node ports = document.child ("nmaprun").child ("host").child ("ports");
    /* Loop through port nodes to identify open ports, their portids, states & services */
    for (port = ports.first_child (); port; port = port.next_sibling ("port")) {
        std::string id = port.attribute ("portid").value ();
        std::string status = port.child ("state").attribute ("state").value ();
        std::string name = port.child ("service").attribute ("name").value ();
        if (name.empty ()) { name = "N/A"; }
        mapPort [id] = std::make_unique <Port> (id, status, name);
        /* Filtered Ports */
        if (status == STATE_FILTERED) {
            numFilter++;
            portsFilter.push_back (id);
        }
        /* Open Ports */
        else if (status == STATE_OPEN) {
            numOpen++;
            portsOpen.push_back (id);
        }
    }
    /* Exit tool if no ports are found */
    if (numOpen == 0 && numFilter ==0) {
        Logger (FAIL, module, PORTS_FOUND_FAIL, LOG_RAW, true).ExitExecution ();
    }
    Logger (PASS, module, PORTS_FOUND_PASS, LOG_RAW, true).LogMessage ();
    return PORTS_FOUND_PASS;
} /* End of GetOpenPorts () */


/*
 * This function prints a summary of ports identified on the target, both filtered & open, along with their services,
 * if found. This also prints appropriate messages if none are found.
 */
void PortHawkScanner::SummaryOpenPorts () {

    std::string module = MOD_PORTS_SUM;
    /* Print filtered ports */
    if (numFilter > 0) {
        std::stringstream optional;
        optional << "Found " << numFilter << " filtered port(s).";
        Logger (INFO, module, FILTER_FOUND_PASS, LOG_RAW, true, optional).LogMessage ();
        std::cout << "\t" << optional.str () << std::endl;
        for (std::string &port : portsFilter) {
            std::cout << "\t" << CYN << "[!] " << RST;
            std::cout << std::setw (5) << std::right << mapPort[port]->portid << " : " << mapPort[port]->service;
            std::cout << std::endl;
        }
    }
    else {
        Logger (INFO, module, FILTER_FOUND_FAIL, LOG_RAW, true).LogMessage ();
    }
    /* Print open ports */
    if (numOpen > 0) {
        std::stringstream optional;
        optional << "Found " << numOpen << " open port(s).";
        Logger (INFO, module, OPEN_FOUND_PASS, LOG_RAW, true, optional).LogMessage ();
        std::cout << "\t" << optional.str () << std::endl;
        for (std::string &port : portsOpen) {
            std::cout << "\t" << BLU << "[!] " << RST;
            std::cout << std::setw (5) << std::right << mapPort[port]->portid << " : " << mapPort[port]->service;
            std::cout << std::endl;
        }
    }
    else {
        Logger (INFO, module, OPEN_FOUND_FAIL, LOG_RAW, true).ExitExecution ();
    }
} /* End of SummaryOpenPorts () */
