/*
 ***********************************************************************************************************************
 * File: utilities.cpp
 * Description: This file contains definitions of commonly used functions that are to be used across the tool or 
 *              otherwise unclassifiable.
 * 
 * Functions:
 *           UsageExit ()
 *           KeyboardInterrupt ()
 *           ExecuteSystemCommand ()
 *           ValidateArguments ()
 *           ConvertToIPAddress ()
 * Author: 0x6D76
 * Copyright (c) 2024 0x6D76 (0x6D76@proton.me)
 ***********************************************************************************************************************
 */

#include <arpa/inet.h>
#include <netdb.h>
#include "logger.hpp"
#include "utilities.hpp"


/*
 * This function prints error condition based on the return code given, then prints usage instructions and exits the
 * operation.
 * :arg: code, ReturnCodes object holding the error code.
 */
void UsageExit (ReturnCodes code) {

    std::cout << GetReturnMessage (code) << std::endl;
    std::cout << "Usage: portHawk <target address>" << std::endl;
    std::cout << "\tExample: 'portHawk target@domain.com' or 'portHawk 127.0.0.1'" << std::endl;
    std::cout << FOOTER << std::endl;
    exit (-1);
}

/*
 * This function handles keyboard interrupt (Ctrl-C) signal sent by the user by printing the appropriate messages and 
 * quits the tool operation.
 * :arg: signal, integer denoting the received signal.
 */
void KeyboardInterrupt (int signal) {

    if (signal == SIGINT) {
        std::cout << GetReturnMessage (KEYBOARD_INT);
        // keepRunning = 0;
        exit (-1);
    }
} /* End of KeyboardInterrupt () */


/*
 * This function executes the given string as a system command, captures its output, copies it to the given 
 * stringstream object and finally returns the success or failure of the execution.
 * :arg: command, const string holding the command to be executed.
 * :arg: output, stringstream object to which the output of the system command is copied to.
 * :return: ReturnCodes object denoting the success or failure of the execution.
 */
ReturnCodes ExecuteSystemCommand (const std::string &command, std::stringstream &output) {

    char buffer [128] = "";
    /* Open a pipe to execute system command and capture its output */
    FILE *pipe = popen (command.c_str (), "r");
    /* Return failure code, upon execution failure */
    if (!pipe) { return CMD_EXEC_FAIL; }
    while (fgets (buffer, sizeof (buffer), pipe) != nullptr) {
        output << buffer;
    }
    pclose (pipe);
    return CMD_EXEC_PASS;

} /* End of ExecuteSystemCommand () */


/*
 * This functions validates the user supplied arguments and returns the result.
 * :arg: argCount, integer denoting the number of user supplied arguments.
 * :arg: values, char pointer to the user supplied arguments.
 * :arg: target, string object holding the converted or validated target IP address.
 * :return: ReturnCodes denoting the success or failure of the operation.
 */
ReturnCodes ValidateArguments (int argCount, char **values, std::string &address) {

    if (argCount != 2) { 
        
        UsageExit (ARG_COUNT_FAIL);
        return ARG_COUNT_FAIL; 
    }
    return ConvertToIPAddress (values [1], address);

} /* End of ValidateArguments () */


/*
 * This function uses getaddrinfo function to convert the given address into its corresponding IP address and returns
 * the result. The main purpose of this function is to indirectly validate the given address, both domain & IP address.
 * :arg: target, const string holding the address to be converted or invalidated.
 * :arg: address, string holding the converted or validated IP address.
 * :return: ReturnCodes denoting the success or failure of address validation.
 */
ReturnCodes ConvertToIPAddress (const std::string &target, std::string &address) {

    struct addrinfo *result;
    struct addrinfo temp {};
    memset (&temp, 0, sizeof (temp));
    temp.ai_family = AF_INET;
    temp.ai_socktype = SOCK_STREAM;

    if (getaddrinfo (target.c_str (), nullptr, &temp, &result) != 0) {
        return TARGET_ADDR_FAIL;
    }

    auto *addr = (struct sockaddr_in*) result->ai_addr;
    address = inet_ntoa (addr->sin_addr);
    freeaddrinfo (result);
    return TARGET_ADDR_PASS;

} /* End of ConvertToIPAddress () */