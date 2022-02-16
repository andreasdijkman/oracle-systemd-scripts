'''
Manipulate .ora write a new config file to STDOUT

Usage:
    python oradot.zip.py -f <filename> -a <SID> -p <parameter> -v <new value> -o <old value>
        --filename  filename to read
        --apply-to  apply to SID/Stanza name (default @all)
        --parameter parameter to change to
        --value     value to be set
        --oldvalue  value to be replaced (ignored by default)

'''

from antlr3 import *;
from antlr3.tree import *;
import OracleNetServicesV3Lexer
import OracleNetServicesV3Parser
import sys
import os
import getopt

from dotora import OraParameter, DotOraFile

import unittest


def usage():
    print(__doc__)


if __name__ == "__main__" and len(sys.argv) >= 2:
    try:
        opts, args = getopt.getopt(sys.argv[1:], "hf:a:p:v:o:", ["help", "filename=", "apply-to=", "parameter=", "value=", "oldvalue="])
    except getopt.GetoptError as err:
        # print help information and exit:
        print(str(err))  # will print something like "option -a not recognized"
        usage()
        sys.exit(2)
    filename  = 'tnsnames.ora'
    applyto   = '@all'
    parameter = None
    value     = None
    oldvalue  = None
    for o, a in opts:
        if o in ("-f", "--filename"):
            filename = a
        elif o in ("-a", "--apply-to"):
            applyto = a
        elif o in ("-p", "--parameter"):
            parameter = a
        elif o in ("-v", "--value"):
            value = a
        elif o in ("-o", "--oldvalue"):
            oldvalue = a                
        elif o in ("-h", "--help"):
            usage()
            sys.exit()
        else:
            assert False, "unhandled option"
    #
    try:
        orafile = DotOraFile(filename)
        #
        if (parameter and value):
            orafile.setvalue(applyto, parameter, value, oldvalue)
        #
        # orafile.upsertalias('AUTOMATIC_IPC', 'OFF')
        # orafile.upsertalias('ABC', '123')
        # orafile.upsertalias('EFG', '456')
        # orafile.upsertalias('EFG', '1234567890')
        orafile.upsertaliasatribute  ('RMAN2', 'DESCRIPTION/ENABLE', 'BROKEN')
        orafile.upsertaliasatribute  ('RMAN2', 'DESCRIPTION/CONNECT_DATA/SERVICE_NAME', 'RMAN_NEW')
        orafile.upsertalias('TRACE_LEVEL_CLIENT', 'ON')
        orafile.upsertalias('RMAN3', '(DESCRIPTION=(CONNECT_DATA=(SERVICE_NAME=RMAN3))(ADDRESS=(PROTOCOL=tcp)(HOST=rman.net)(PORT=1521)))')

        orafile.removealias('ORA12')

        print(orafile)

    except ValueError as error:
        print(error)


