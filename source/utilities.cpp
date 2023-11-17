/*
 ***********************************************************************************************************************
 * File: utilities.cpp
 * Description: This file contains definitions of commonly used functions to be used across the tool or otherwise
 * unclassifiable
 * Functions:
 *              int ValidateArguments (int argCount, char **values, std::string &target)
 *              int ConvertToIPAddress (const std::string &target, std::string &address)
 *              int InitializeTool (int argCount, char **values, std::string &address)
 *              int ExecuteSystemCommand (const std::string &command, std::stringstream &output)
 *              std::string ReplacePlaceHolders (const std::string &command,
                                                 const std::unordered_map<std::string, std::string> &placeHolders)
 * Author: 0x6D76
 * Copyright (c) 2023 0x6D76 (0x6D76@proton.me)
 ***********************************************************************************************************************
 */

#include "logger.hpp"
#include "utilities.hpp"

/*
 * This function validates user-supplied arguments, first by validating the number of arguments given, then by
 * validating the individual arguments themselves.
 * :arg: argCount, integer value denoting the number of user-supplied arguments.
 * :arg: values, char pointer to the user-supplied arguments.
 * :arg: target, string object holding the converted or validated IP address.
 * :return: integer value denoting the success or failure of the operation.
 */
int ValidateArguments (int argCount, char **values, std::string &target) {

    if (argCount != 2) { return ARG_NUM_FAIL; }
    return ConvertToIPAddress (values [1], target);
} /* End of ValidateArguments () */


/*
 * This function uses getaddrinfo function to convert the given address into its corresponding IP address and returns
 * the result. The main purpose of this function is to indirectly validate the given address, both domain and IP
 * address.
 * :arg: target, const string holding the address to be converted or validated.
 * :arg: address, string holding the converted or validated IP address.
 * :return: integer value denoting the success or failure of IP conversion.
 */
int ConvertToIPAddress (const std::string &target, std::string &address) {

    struct addrinfo *result;
    struct addrinfo temp{};
    memset (&temp, 0, sizeof (temp));
    temp.ai_family = AF_INET;
    temp.ai_socktype = SOCK_STREAM;
    if (getaddrinfo (target.c_str(), nullptr, &temp, &result) != 0) { return TARGET_ADDR_FAIL; }
    auto *addr = (struct sockaddr_in*) result->ai_addr;
    address = inet_ntoa (addr->sin_addr);
    freeaddrinfo (result);
    return TARGET_ADDR_PASS;
} /* End of ConvertToIPAddress () */


/*
 * This function initializes the tool by validating the arguments, creating necessary directories and calling the
 * support function to print tool header.
 * :arg: argCount, integer value denoting the number of arguments supplied.
 * :arg: values, char pointer to the user-supplied arguments.
 * :arg: address, string holding the validated IP address.
 * :return: integer value denoting the success or failure of the operation.
 */
int InitializeTool (int argCount, char **values, std::string &address) {

    std::string module = MOD_INIT;
    int retCode = ValidateArguments (argCount, values, address);
    /* Exit Execution if arguments validation has failed */
    if (retCode < 0) {
        Logger (FAIL, module, retCode, LOG_RAW, true).ExitExecution ();
    }
    try { std::filesystem::create_directories (DIR_PORTS); }
    catch (const std::filesystem::filesystem_error &err) {
        std::stringstream error {};
        error << err.what ();
        Logger (FAIL, module, DIR_CREATE_FAIL, LOG_RAW,
                true, error).ExitExecution ();
    }
    Logger (HEAD).PrintToolLabel ();
    Logger (INFO, module, DIR_CREATE_PASS, LOG_RAW).LogMessage ();
    return TARGET_ADDR_PASS;
} /* End of InitializeTool () */


/*
 * The function executes the given string as a system command, captures its output, copies it to the given
 * stringstream object and then returns the success or failure of the execution.
 * :arg: command, const string holding the command to be executed.
 * :arg: output, stringstream object to which the output of the system command is copied to.
 * :return: integer value denoting the success or failure of the execution.
 */
int ExecuteSystemCommand (const std::string &command, std::stringstream &output) {

    char buffer [128] = "";
    /* Open a pipe to execute system command and capture its output */
    FILE *pipe = popen (command.c_str (), "r");
    /* Return failure code if command execution has failed */
    if (!pipe) { return CMD_EXEC_FAIL; }
    /* Read and copy the output of the command line by line into a stringstream object */
    while (fgets (buffer, sizeof (buffer), pipe) != nullptr) { output << buffer; }
    pclose (pipe);
    return CMD_EXEC_PASS;
} /* End of ExecuteSystemCommand () */


/*
 * This function gets a string and replaces the placeholders with the values supplied as an unordered_map.
 * :arg: command, string on which the placeholders are to be replaced.
 * :arg: placeHolders, unordered_map object containing the placeholder and string to replace it with.
 * :return: string holding the replaced string.
 */
std::string ReplacePlaceHolders (const std::string &command,
                                 const std::unordered_map<std::string, std::string> &placeHolders) {

    std::string result = command;
    /* Loop through placeholders map to replace */
    for (const auto &placeHolder : placeHolders) {
        std::string key = "$" + placeHolder.first;
        size_t position = result.find (key);
        /* Check and replace only if placeholder is present in the command */
        while (position != std::string::npos) {
            result.replace (position, key.length (), placeHolder.second);
            position = result.find (key, position + placeHolder.second.length ());
        }
    }
    return result;
} /* End of ReplacePlaceHolders () */
