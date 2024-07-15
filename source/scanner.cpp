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

    std::stringstream command {};
    std::stringstream output {};
    std::string xmlOpen = DIR_BASE + "OpenPorts.xml";

    command << BASE_NMAP_OPEN << xmlOpen << " " << address;
    /* Execute NMAP scan and return failure if it fails */
    if (ExecuteSystemCommand (command.str (), output) == CMD_EXEC_FAIL) {
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
 *
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
}