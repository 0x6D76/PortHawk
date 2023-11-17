/*
 ***********************************************************************************************************************
 * File: scanner.cpp
 * Description: This file contains definitions of various member functions of different classes that are to be used as
 * part of the scanner module.
 * Functions:
 *           Port
 *              Port ()
 *              int DeepServiceProbe (const std::string &address)
 *              int PortNmapScan (const std::string &address, const std::string &module)
 *           PortHawkScanner
 *              PortHawkScanner ()
 *              int GetOpenPorts ()
 *              void SummaryOpenPorts ()
 *              int MultiThreadedServicesProbe (int maxThreads)
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
    dirPort = DIR_PORTS + portid + "/";
    xmlPortNmap = dirPort + "deep_probe_nmap.xml";
    namePortLog = dirPort + "deep_probe_raw.log";
    vulns = {};
    scansCompleted = {};
    scansFailed = {};
} /* End of Port () */


/*
 * This function probes the identified open ports, by running NMAP scans to identify basic information and
 * vulnerabilities about the running services. This furthers the probe by running all the scans mapped to individual
 * services on "services.xml" file.
 * :arg: address, const string holding the IP address of the target.
 * :return: integer value denoting the success or failure of the operation.
 */
int Port::DeepServiceProbe (const std::string &address) {
    std::string scan;
    std::string module = MOD_DEEP_SRV_SCAN + "-" + portid + "/" + service;
    Logger (INFO, module, DEEP_SRV_INFO, LOG_RAW).LogMessage ();
    Logger (INFO, module, DEEP_SRV_INFO, namePortLog).LogMessage ();
    scan = "NMAP Port Scan";
    if (PortNmapScan (address, module) < 0) {
        Logger (FAIL, module, DEEP_SRV_SCAN_FAIL, LOG_RAW, true).LogMessage ();
        scansFailed.push_back (scan);
        return DEEP_SRV_SCAN_FAIL;
    }
    Logger (PASS, module, DEEP_SRV_SCAN_PASS, LOG_RAW, true).LogMessage ();
    return 0;
}


/*
 * This function runs NMAP deeper scan against the target on the specified port and identifies its associated
 * service, product, version & extrainfo.
 * :arg: address, const string holding the target IP address.
 * :arg: module, const string holding the name of the module.
 * :return: integer value denoting the success or failure of the operation.
 */
int Port::PortNmapScan (const std::string &address, const std::string &module) {

    /* Running NMAP deep scanning */
    std::string command {};
    std::stringstream output {};
    std::unordered_map <std::string, std::string> placeHolders = {
            {ID, portid},
            {XML_FILE, xmlPortNmap},
            {TARGET, address},
    };
    command = ReplacePlaceHolders (BASE_NMAP_PORT, placeHolders);
    if (ExecuteSystemCommand (command, output) < 0) {
        Logger (FAIL, module, NMAP_PORT_FAIL, namePortLog, false, output).LogMessage ();
        return NMAP_PORT_FAIL;
    }
    Logger (PASS, module, NMAP_PORT_PASS, namePortLog, false, output).LogMessage ();
    /* Parsing NMAP scan results */
    pugi::xml_document document;
    if (!document.load_file (xmlPortNmap.c_str())) {
        Logger (FAIL, module, XML_PORT_FAIL, namePortLog, false, output).LogMessage ();
        return XML_PORT_FAIL;
    }
    pugi::xml_node hostNode = document.child ("nmaprun").child ("host");
    pugi::xml_node portNode = hostNode.child("ports").child("port");
    /* Extracting service information */
    pugi::xml_node serviceNode = portNode.child ("service");
    service = serviceNode.attribute ("name").as_string ();
    product = serviceNode.attribute ("product").as_string ();
    version = serviceNode.attribute ("version").as_string ();
    /* Extracting OS information */
    pugi::xml_node osNode = hostNode.child ("os").child ("osmatch");
    if (!osNode.empty ()) { osName = osNode.attribute ("name").value(); }
    /* Extracting vulnerability information */
    pugi::xml_node scriptNode;
    for (scriptNode = portNode.child("script"); scriptNode; scriptNode = scriptNode.next_sibling ("script")) {
        std::string scriptId = scriptNode.attribute("id").value();
        std::string scriptOutput = scriptNode.child_value();
        /* Check if vulnerability is marked as "vulnerable" */
        if (scriptOutput.find("vulnerable") != std::string::npos) {
            vulns.push_back (scriptId);
        }
    }
    Logger (PASS, module, XML_PORT_PASS, namePortLog).LogMessage ();
    return NMAP_PORT_PASS;
} /* End of PortNmapScan () */


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
    /* Check and exit execution if loading XML file has failed */
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


/*
 * This function gets open ports from the portsOpen data member and uses them to make multithreaded calls to the
 * DeepServiceProbe member function Port object.
 * :arg: maxThreads, integer value denoting maximum number of threads to use, default value- 20
 * :return: integer value denoting the success or failure of the operation.
 */
int PortHawkScanner::MultiThreadedServicesProbe (int maxThreads) {

    std::string module = MOD_MULTI_SCAN;
    std::vector <std::thread> threads;
    Logger (INFO, module, MULTI_THREAD_PROBE_INFO, LOG_RAW, true).LogMessage ();

    threads.reserve (std::min (maxThreads, static_cast <int> (portsOpen.size())));
    for (const std::string &portKey : portsOpen) {
        threads.emplace_back ([&, portKey] () {
            mutexXmlAccess.lock ();
            std::unique_ptr <Port> &port = mapPort [portKey];
            if (port) { port->DeepServiceProbe (address); }
            mutexXmlAccess.unlock ();
        });
    }
    /* Join all threads and wait for them to complete */
    for (std::thread& thread : threads) { thread.join(); }
    return MULTI_THREAD_PROBE_PASS;
} /* End of MultithreadedServicesProbe () */
