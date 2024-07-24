/*
 ***********************************************************************************************************************
 * File: scanner.cpp
 * Description: This file contains definitions of member functions and support functions associated with scanning
 *              functionalities.
 * Functions:
 *           Port
 *              Port ()
 *           Host
 *              Host ()
 *              AddPortToHost ()
 * Author: 0x6D76
 * Copyright (c) 2024 0x6D76 (0x6D76@proton.me)
 ***********************************************************************************************************************
 */
#include "scanner.hpp"


/*
 * Instantiates a new object of Port class.
 * :arg: id, constant string holding the port id.
 * :arg: status, constant string holding the current state of the port.
 * :arg: name, const string holding the name of the service running on the port.
 */
Port::Port (const std::string &id, const std::string &status, const std::string &name) 
            : portid (id), state (status), service (name) {

} /* End of Port () */


/*
 * This function runs deep NMAP script scan against the target on the specified port to identify its associated service,
 * product, version and OS information.
 * :arg: target, string holding the target IP address.
 * :arg: masterLog, Logger object holding the master log to which the messages are to be logged.
 * :return: ReturnCode object denoting the success or failure of the operation.
 */
int Port::DeepServiceProbe (const std::string &target, Logger masterLog) {

    std::string command {};
    std::stringstream optional {};
    std::stringstream output {};
    pugi::xml_document document {};
    std::string xmlDeep = DIR_PORTS + portid + ".xml";
    std::string logFile = DIR_LOGS + portid + ".log";
    Logger portLog (logFile);

    optional << "Port: " << portid;
    std::unordered_map <std::string, std::string> placeHolders = {
        {ID, portid},
        {XML_FILE, xmlDeep},
        {TARGET, target},
    };
    portLog.Header ();
    portLog.Log (INFO, MOD_DEEP_SCAN, DEEP_SERVICE_INFO, false);
    command = ReplacePlaceHolders (BASE_NMAP_DEEP, placeHolders);
    /* Executing NMAP scan */
    if (ExecuteSystemCommand (command, output) == CMD_EXEC_FAIL) {
        portLog.Log (FAIL, MOD_DEEP_SCAN, DEEP_SERVICE_NMAP_FAIL, false);
        masterLog.Log (FAIL, MOD_DEEP_SCAN, DEEP_SERVICE_NMAP_FAIL, true, optional);
        return DEEP_SERVICE_FAIL;
    }
    portLog.Log (PASS, MOD_DEEP_SCAN, DEEP_SERVICE_NMAP_PASS, false);
    /* Parsing the XML file */
    if (!document.load_file (xmlDeep.c_str ())) {
        portLog.Log (FAIL, MOD_DEEP_SCAN, DEEP_SERVICE_XML_FAIL, false);
        masterLog.Log (FAIL, MOD_DEEP_SCAN, DEEP_SERVICE_XML_FAIL, true, optional);
        return DEEP_SERVICE_FAIL;
    }
    portLog.Log (PASS, MOD_DEEP_SCAN, DEEP_SERVICE_XML_PASS, false);
    pugi::xml_node nodeHost = document.child ("nmaprun").child ("host");
    pugi::xml_node nodePort = nodeHost.child ("ports").child ("port");
    pugi::xml_node nodeService = nodePort.child ("service");
    /* Extracting service information */
    service = nodeService.attribute ("name").as_string ();
    product = nodeService.attribute ("product").as_string (); 
    version = nodeService.attribute ("version").as_string ();
    /* Extracting OS information */
    pugi::xml_node nodeOS = nodeHost.child ("os").child ("osmatch");
    if (!nodeOS.empty ()) { osName = nodeOS.attribute ("name").value (); }
    /* Extracting vulnerability information */
    pugi::xml_node nodeScript;
    for (nodeScript = nodePort.child ("script"); nodeScript; nodeScript = nodeScript.next_sibling ("script")) {
        std::string scriptID = nodeScript.attribute ("id").value ();
        std::string scriptOP = nodeScript.child_value ();
        if (scriptOP.find ("vulerable") != std::string::npos) {
            vulnerabilities.push_back (scriptID);
        }
    }
    portLog.Log (PASS, MOD_DEEP_SCAN, DEEP_SERVICE_PASS, false);
    masterLog.Log (PASS, MOD_DEEP_SCAN, DEEP_SERVICE_PASS, true, optional);

    return DEEP_SERVICE_PASS;

} /* End of DeepServiceProbe () */


/*
 * Instantiates a new object of Host class.
 * :arg: addr, constant string holding the validated address of the target.
 */
Host::Host (const std::string &addr)
            : address (addr), numOpen (0), numFilter (0) {

} /* End of Host () */


/*
 * This function adds Ports object to Host object based on the current state of the port, to either Open Ports or
 * Filtered ports.
 * :arg: port, Port object holding the port information of the current port.
 */
void Host::AddPortToHost (const Port &port) {

    if (port.state == STATE_OPEN) {
        openPorts.push_back (port);
        numOpen++;
    } else if (port.state == STATE_FLTR) {
        filterPorts.push_back (port);
        numFilter++;
    }

} /* End of AddPortToHost () */


/*
 * This function executes NMAP scan agains the target and parses the XML file to identify open and filtered ports, 
 * along with their respective states, portids and service names.
 * :arg: ojLog, Logger object to which the messages are to be logged.
 * :return: ReturnCodes object denoting the success/failure of the operation.
 */
ReturnCodes Host::GetOpenPorts (Logger objLog) {

    std::string command {};
    std::stringstream output {};
    std::string xmlOpen = DIR_BASE + "OpenPorts.xml";
    std::unordered_map <std::string, std::string> placeHolders = {
        {XML_FILE, xmlOpen},
        {TARGET, address},
    };
    command = ReplacePlaceHolders (BASE_NMAP_OPEN, placeHolders);
    /* Execute NMAP scan and return failure if it fails */
    if (ExecuteSystemCommand (command, output) == CMD_EXEC_FAIL) {
        objLog.Log (FAIL, MOD_NMAP_OPEN, OPEN_NMAP_FAIL, true);
        return OPEN_NMAP_FAIL;
    }
    objLog.Log (PASS, MOD_NMAP_OPEN, OPEN_NMAP_PASS, false);
    
    /* Parsing NMAP scan results */
    pugi::xml_document document;

    if (!document.load_file (xmlOpen.c_str ())) {
        objLog.Log (FAIL, MOD_XML_OPEN, OPEN_XML_FAIL, true);
        return OPEN_XML_FAIL;
    }
    pugi::xml_node port;
    pugi::xml_node ports = document.child ("nmaprun").child ("host").child ("ports");
    /* Loop through port nodes to identify ports, their respective portids, states & services. */
    for (port = ports.first_child (); port; port = port.next_sibling ("port")) {
        std::string id = port.attribute ("portid").value ();
        std::string status = port.child ("state").attribute ("state").value ();
        std::string name = port.child ("service").attribute ("name").value ();

        if (name.empty ()) { name = "N/A"; }
        /* Add corresponding port object to the target Host if the port's current state is not closed. */
        if (status != STATE_CLSD) { AddPortToHost (Port (id, status, name)); }
    }

    if (numOpen == 0 && numFilter == 0) {
        objLog.Log (FAIL, MOD_XML_OPEN, PORT_FOUND_FAIL, true);
        return PORT_FOUND_FAIL;
    }
    objLog.Log (PASS, MOD_XML_OPEN, PORTS_FOUND_PASS, true);
    return PORTS_FOUND_PASS;
    
} /* End of GetOpenPorts () */


/*
 * This function prints a summary of open and filtered ports identified on the target, along with their respective
 * service names, if identified.
 * :arg: logObj, Logger object to which the messages are to be logged.
 */
void Host::PrintOpenScanSummary (Logger logObj) {

    /* module = MOD_SUM_PORTS */
    if (numFilter > 0) {
        std::stringstream optional;
        optional << "Found " << numFilter << " filtered port(s).";
        logObj.Log (INFO, MOD_SUM_PORTS,FILTER_FOUND_PASS, true, optional);
        std::cout << "\t" << optional.str () << std::endl;

        for (const auto &port : filterPorts) {
            std::cout << "\t" << CYN << "[!] " << RST;
            std::cout << std::setw (5) << std::right << port.portid << " : " << port.service << std::endl;
        }
    } 
    else {
        logObj.Log (INFO, MOD_SUM_PORTS, FILTER_FOUND_FAIL, false);
    }

    if (numOpen > 0) {
        std::stringstream optional;
        optional << "Found " << numOpen << " open port(s).";
        logObj.Log (INFO, MOD_SUM_PORTS,OPEN_FOUND_PASS, true, optional);
        std::cout << "\t" << optional.str () << std::endl;

        for (const auto &port : openPorts) {
            std::cout << "\t" << BLU << "[!] " << RST;
            std::cout << std::setw (5) << std::right << port.portid << " : " << port.service << std::endl;
        }
    } 
    else {
        logObj.Log (INFO, MOD_SUM_PORTS, OPEN_FOUND_FAIL, true);
    }
} /* End of PrintOpenScanSummary () */


/*
 * This function creates necessary threads and make multi-threaded calls to DeepServiceProbe with the target address
 * as its parameter.
 * :arg: objFile, Logger object to which the messages are to be logged.
 * :arg: maxThreads, integer denoting the number of threads, default value is MAX_THREADS (20).
 * :return: ReturnCodes object denoting the success/failure of the operation.
 */
int Host::MultitreadedServiceProbe (Logger objFile, int maxThreads) {

    /* module = MOD_MULTI_SCAN */
    std::vector <std::thread> threads;
    objFile.Log (INFO, MOD_MULTI_SCAN, MULTI_THREAD_PROBE_INFO, true);
    threads.reserve (std::min (maxThreads, static_cast <int> (openPorts.size ())));
    
    for (Port &port : openPorts) {
        threads.emplace_back ([&]() {
            {
                std::lock_guard <std::mutex> lock (mtx);
                port.DeepServiceProbe (this->address, objFile);
            }
        });
    }

    for (std::thread &thread : threads) {
        if (thread.joinable ()) {
            thread.join ();
        }
    }
    objFile.Log (PASS, MOD_MULTI_SCAN, MULTI_THREAD_PROBE_PASS, true);
    return MULTI_THREAD_PROBE_PASS;
} /* End of MultithreadedServiceProbe () */