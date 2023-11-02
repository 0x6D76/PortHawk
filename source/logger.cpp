/*
 ***********************************************************************************************************************
 * File: logger.cpp
 * Description: This file contains definitions of support functions and member functions associated with logging
 * functionalities.
 * Functions:
 *           string GetReturnMessage ()
 *           string GetCurrentTime ()
 *           Logger
 *              Logger ()
 *              void PrintLabel ()
 *              void FormatLog ()
 *              void LogMessage ()
 *              void ExitExecution ()
 * Author: 0x6D76
 * Copyright (c) 2023 0x6D76 (0x6D76@proton.me)
 ***********************************************************************************************************************
 */
#include "logger.hpp"

/*
 * This function enumerates the ReturnMessages map structure and returns the message associated with the given return
 * code.
 * :arg: returnCode, integer value denoting the return code for the message to be fetched.
 * :return: string holding the return message associated with the return code.
 */
std::string GetReturnMessage (ReturnCodes returnCode) {

    auto find = ReturnMessages.find (returnCode);
    return (find != ReturnMessages.end ()) ? find->second : UNKNOWN;
} /* End of GetReturnMessage () */


/*
 * This function gets and formats the current timestamp in [dd-mm-yy hh:mm:ss] format and returns it.
 * :return: string holding the current timestamp.
 */
std::string GetCurrentTime () {

    time_t now = time (nullptr);
    char timestamp [21];
    strftime(timestamp, sizeof (timestamp), "[%d-%m-%y %H:%M:%S]", localtime (&now));
    return timestamp;
} /* End of GetCurrentTime () */


/*
 * Constructor for a new logger object, with a single parameter, used to print header or footer portion of the tool.
 * :arg: type, integer value denoting header or footer.
 */
Logger::Logger (int type) {

    severity = type;
    message = (severity == HEAD) ? HEADER : FOOTER;
    nameLog = LOG_RAW;
    retCode = 0;
    verbose = true;
} /* End of Logger () */


/*
 * Constructor for a new Logger object, used to print or log messages.
 * :arg: type, integer value denoting the severity of the log.
 * :arg: nameModule, constant string holding the name of the current module.
 * :arg: code, integer value denoting the return code of the operation.
 * :arg: nameFile, const string holding the name of the log file.
 * :arg: output, bool value indicating whether to print the log to STDOUT.
 * :arg: opt, stringstream object holding the optional message to be logged.
 */
Logger::Logger (int type, const std::string &nameModule, int code, const std::string &nameFile, bool output,
                const std::stringstream &opt) {

    severity = type;
    module = nameModule;
    retCode = code;
    nameLog = nameFile;
    verbose = output;
    message = GetReturnMessage (static_cast <ReturnCodes> (retCode));
    optional << opt.rdbuf ();
} /* End of Logger () */


/*
 * This function formats and prints the header or footer of the tool, based on the initialized data member (severity).
 */
void Logger::PrintToolLabel () {

    std::stringstream strVerb {};
    std::stringstream strFile {};
    std::string color = (severity == HEAD) ? BLU : RED;
    int padding = (WIDTH - message.length ()) / 2;
    strVerb << LINE << "\n" << color << std::setw (padding + message.length()) << message << RST << "\n"
            << LINE << std::endl;
    strFile << LINE << "\n" << std::setw (padding + message.length ()) << message << "\n" << LINE << std::endl;
    std::cout << strVerb.str ();
    fileRaw.open (nameLog, std::ios::app);
    fileRaw << strFile.str ();
    fileRaw.close ();
} /* End of PrintToolLabel () */


/*
 * The function formats the log message based on the initialized data members, to be ready for writing to log file
 * and/or printing to the log file.
 * :arg: strVerbose, stringstream object holding the content to be printed to STDOUT.
 * :arg: strFile, stringstream object holding the content to be written to the initialized log file.
 */
void Logger::FormatLog (std::stringstream &strVerbose, std::stringstream &strFile) {

    std::string strSeverity;
    std::string color;
    switch (severity) {
        case PASS:
            strSeverity = "[PASS]";
            color = GRN;
            break;
        case FAIL:
            strSeverity = "[FAIL]";
            color = RED;
            break;
        case INFO:
            strSeverity = "[INFO]";
            color = YEL;
            break;
    }
    if (verbose) {
        strVerbose << color << strSeverity << RST << GetCurrentTime () << MAG << "[" << module << "] " << RST
                   << message << std::endl;
    }
    strFile << strSeverity << GetCurrentTime () << "[" << module << "] " << message << std::endl;
    /* Add optional message, if initialized with, to the strFile object */
    if (optional) { strFile << optional.str () << std::endl; }
    strFile << HALF_LINE << std::endl;
} /* End of FormatLog () */


/*
 * This function calls the FormatLog function to format the log message based on the initialized object and logs them
 * accordingly.
 */
void Logger::LogMessage () {

    std::stringstream strVerbose {};
    std::stringstream strFile {};
    FormatLog (strVerbose, strFile);
    /* Print the log message to STDOUT, if verbose is enabled */
    if (verbose) { std::cout << strVerbose.str (); }
    fileRaw.open (nameLog, std::ios::app);
    fileRaw << strFile.str ();
    fileRaw.close ();
} /* End of LogMessage () */


/*
 * This function logs the content of the initialized object to both STDOUT and raw log file, then proceeds to free
 * the dynamically allocated memories and finally exits the execution of the tool.
 */
void Logger::ExitExecution () {

    LogMessage ();
    Logger (FOOT).PrintToolLabel ();
    /*
     * Free up dynamically allocated memories
     */
    exit (retCode);
} /* End of ExitExecution () */