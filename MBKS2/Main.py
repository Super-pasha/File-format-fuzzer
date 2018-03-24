import threading
import os
import getopt
import time
import utils
import FuzzingLib

from sys import argv, exc_info
from shutil import copyfile
from random import randint

from pydbg import *
from pydbg.defines import * 


class ProcCrashTester:
    """ it launches program and catches its crashes """ 

    def __init__(self, exe_name, conf_name, crashes_dir, seconds):
        """ 
        test_dir - where are exe_file, and conf_file are placed
        exe_name, conf_name - names of files
        crashes_dir - where to save results
        seconds - how much time is provided to wait for crash 

        """

        # additional debug exception codes
        EXCEPTION_ARRAY_BOUNDS_EXCEEDED = 0xC000008C
        EXCEPTION_FLT_STACK_CHECK 		= 0xC0000092
        EXCEPTION_INT_OVERFLOW 			= 0xC0000095
        EXCEPTION_STACK_OVERFLOW 		= 0xC00000FD
        
        EXCEPTION_HEAP_CORRUPTION		= 0xC0000374
        EXCEPTION_STACK_BUFFER_OVERRUN  = 0xC0000409    

        self.exe_path = exe_name
        self.conf_path = conf_name 

        self.crashes_dir = crashes_dir 
        self.seconds = seconds
        
        self.event = threading.Event()
        self.dbg = pydbg() 
        self.crashed = False

        # exception codes
        self.gExceptEvCodes = {
            EXCEPTION_ACCESS_VIOLATION          :  ( "EXCEPTION_ACCESS_VIOLATION"     , self.check_accessv   ),
            EXCEPTION_ARRAY_BOUNDS_EXCEEDED     :  ( "EXCEPTION_ARRAY_BOUNDS_EXCEEDED", self.check_accessv   ),
            EXCEPTION_FLT_STACK_CHECK           :  ( "EXCEPTION_FLT_STACK_CHECK"      , self.check_accessv   ),
            EXCEPTION_INT_OVERFLOW              :  ( "EXCEPTION_INT_OVERFLOW"         , self.check_accessv   ),
            EXCEPTION_STACK_OVERFLOW            :  ( "EXCEPTION_STACK_OVERFLOW"       , self.check_accessv   ),
            EXCEPTION_HEAP_CORRUPTION           :  ( "EXCEPTION_HEAP_CORRUPTION"      , self.check_accessv   ),
            EXCEPTION_STACK_BUFFER_OVERRUN      :  ( "EXCEPTION_STACK_BUFFER_OVERRUN" , self.check_accessv   ),
            EXIT_PROCESS_DEBUG_EVENT            :  ( "EXIT_PROCESS_DEBUG_EVENT"       , self.check_exit_code ),
        }
        
    def record_crash(self, dump):
        """ saves error information results
        to result_dir_path\\x where directory x will be created 
        and will contain config file from conf_path and dump """

        r = randint(ord('A'), ord('Z')) + randint(ord('a'), ord('z'))
        dir_name = "Crash at " + time.strftime("%H-%M-%S %d.%m.%Y") + ' ' + str(r)
        path = self.crashes_dir + '\\' + dir_name
        os.mkdir(path)
     
        file = open(path + '\\' + 'crash_report.txt', 'w')
        file.write(dump)
        file.close()

        copyfile(self.conf_path, path + '\\' + self.conf_path)

    def check_accessv(self, dbg): 
        """ this is access violation handler """
    
        # skip first-chance exceptions 
        if dbg.dbg.u.Exception.dwFirstChance: 
            return DBG_EXCEPTION_NOT_HANDLED 
        
        s = ''
        code = dbg.dbg.u.Exception.ExceptionRecord.ExceptionCode
    
        # search for exception code in map
        if self.gExceptEvCodes.has_key(code):
            s = "Exception code: " + self.gExceptEvCodes[code][0] + "\n\n"
    
        try:
            # get info
            crash_bin = utils.crash_binning.crash_binning() 
            crash_bin.record_crash(dbg) 
        
            # save info
            s += crash_bin.crash_synopsis() 
        
        except:
            s += "Unexpected error:" + str(exc_info()[0])

        self.record_crash(s)
        #print s
        
        # terminate process and signal that program has crashed
        self.crashed = True
        self.dbg.terminate_process() 
        
        return DBG_EXCEPTION_NOT_HANDLED 
    
    def check_exit_code(self, dbg):
        """ check process exit code and set an event"""

        exit_code = dbg.dbg.u.ExitProcess.dwExitCode;
    
        if exit_code != 0:
            print "That might be interesting. Process exit code: %x" % exit_code 
    
        # signal that program finished
        self.event.set()

    def setCallbacks(self):
        """ set callback functions for all types of access violation"""

        for key, val in self.gExceptEvCodes.items():
            self.dbg.set_callback(key, val[1]) 

    def debugger_thread(self):
        """ thread that launches vulnerable program """
        
        #try:
        self.dbg.load(self.exe_path)
        self.setCallbacks()
        self.dbg.run()

    def monitor(self):
        """ thread that determines whether program is vulnerable or not """
        
        #print "Launching test"
    
        t = threading.Thread(target=self.debugger_thread)
        t.setDaemon(0)
        t.start()   
    
        b = self.event.wait(self.seconds)
      
        # program hasn't crashed in n seconds
        if (b == False):
    
            print('Program has not crashed. Terminating...')
    
            # terminate
            try:
                self.dbg.terminate_process()
            except:
                print('Error while terminating process.\nMaybe it has been already stopped')
    
    
        # program maybe crashed
        else:
            if self.crashed:
                print('Program has crashed! Congratulations!!!')
            else:
                print('Program has not crashed')
    
        t.join()


def monitor_func(args):

    # args = (exe, conf, crash, wait)
    assert len(args) == 4

    procTester = ProcCrashTester(args[0], args[1], args[2], args[3])
    procTester.monitor()

def usage_manual():
    
    print('Manual mode usage:')
    print('insert   <start> <data> - insert bytes <data> into file at position <start>')
    print('insert   <start> <hexbyte> <count> - insert <byte> * <count> bytes into file at position <start>')
    print('change   <start> <data> - change bytes beginning from <start> on <data>')
    print('change   <start> <hexbyte> <count> - change bytes beginning from <start> on <byte> * <count>')
    print('remove   <start> <end>  - remove bytes in file [start-end)')
    print('show     <start> <end>  - show bytes in file [start, end)')
    print('save     <start> <end>  - save bytes [start, end)')
    print('restore - restore bytes saved by "save" command')
    print('run     - launch program for execution')
    print('analyze - analyze config file format')
    print('exit    - to exit')
    print('help    - to help')
    print('example: remove 1 5')
    print('example: change 1 aaa')
    print('example: change 12 FF 8')
    print('example: insert 1 aaa')
    print('example: insert 12 0 8')
    print('example: save 1 5')

def user_manual(exe, conf, crash, wait, cdir):
    
    """
    when user launches manual mode he can enter 
    commands to modify conf file and then check if program crashes

    """
    
    file = open(conf, 'rb+')
    saved_start = None
    saved_bytes = None

    usage_manual()
    
    while 1: 
        
        try:
            print '\n'

            command = raw_input(">>> ")
            com = command.split(' ')

            if not command:
                continue

            if len(com) == 1:
                
                if com[0] == 'exit':
                    file.close()
                    break
                elif com[0] == 'restore':
                     FuzzingLib.changeFileBytes(file, saved_start, saved_bytes)
                elif com[0] == 'help':
                    usage_manual()
                elif com[0] == 'run':
                    monitor_func((exe, conf, crash, int(wait)))
                elif com[0] == 'analyze':
                    FuzzingLib.analyzeFiles(cdir, conf)
                else:
                    print('Unknown command')

            elif len(com) == 3:

                if com[0] == 'insert':
                     FuzzingLib.insertFileBytes(file, com[1], com[2])

                elif com[0] == 'remove':
                     FuzzingLib.removeFileBytes(file, com[1], com[2])

                elif com[0] == 'show':   
                     FuzzingLib.showFileBytes(file, com[1], com[2])

                elif com[0] == 'change': 
                     FuzzingLib.changeFileBytes(file, com[1], com[2])

                elif com[0] == 'save':
                     saved_start = int(com[1])
                     saved_bytes = FuzzingLib.getFileBytes(file, com[1], com[2])
                else:
                    print('Unknown command')

            elif len(com) == 4: # 1 - pos, 2 - byte, 3 - how many

                if com[0] == 'insert':
                    if int(com[2], 16) == 0:
                        FuzzingLib.insertFileBytes(file, com[1], b'\x00' * int(com[3]))
                    else:
                        FuzzingLib.insertFileBytes(file, com[1], FuzzingLib.int_to_bytes(int(com[2], 16)) * int(com[3]))

                elif com[0] == 'change': 
                    if int(com[2], 16) == 0:
                        FuzzingLib.changeFileBytes(file, com[1], b'\x00' * int(com[3]))
                    else:
                        FuzzingLib.changeFileBytes(file, com[1], FuzzingLib.int_to_bytes(int(com[2], 16)) * int(com[3]))
                else:
                    print('Unknown command')

            else:
                print('Unknown command')
        except:
            print('Operation is not performed: bad parameter')


def print_usage():
    """ prints usage """

    print('\nUsage: [ * - nesessary parameter ]\n')
    print('--exe   *  <string>    - path to .exe file for testing') 
    print('--conf  *  <string>    - name of main configuration file in cdir')
    print('--cdir  *  <string>    - path to directory where main config file and other config files are placed')
    print('--wait     <int>       - time to wait for program crash in <int> seconds\n')
    print('--skip     <int>       - do not fuzz region of file if its size more than <int>\n')
                      
    print('--help     - usage\n')
    print('--terminal - run fuzzer in manual mode\n')
    
    print('example: script.py --exe=1.exe --conf=config_1')
    print('--cdir=D:\workflow --wait=5 --skip=300\n')


if __name__ == "__main__":

    """ place in one folder:                                                             
         
         - fuzzer program
         - program file and files used by program
         - config file used by program

     fuzzer needs:

         1) name config file                                                 --conf=
         2) path to folder where conf files are placed                       --cdir=
         3) name of exe file to test                                         --exe=
        
         optional:
         5) wait
         6) skip
         7) terminal
         8) help
    """

    try: 
        opts, args = getopt.getopt(argv[1:], '', ['help', 'cdir=', 'exe=', 'conf=', 'skip=', 'wait=', 'terminal']) 
    
    except getopt.GetoptError as err: 
        print(str(err))
        exit(-1)
    
    skip = exe = conf = cdir = crash = wait = None
    terminal = False
    crash = "Crash reports" 

    for option, value in opts: 
        
        if (option == "--terminal"):
            terminal = True
        elif (option == "--help"):
            print_usage()
            exit()
        elif option == "--exe": 
            exe = value 
        elif option == "--conf": 
            conf = value
        elif option == "--cdir":
            cdir = value
        elif option == "--wait":
            wait = value
        elif option == "--skip":
            skip = value
                   
    if wait is None:
        wait = 10
    if skip is None:
        skip = 200

    if file is None or conf is None or dir is None:  
        
        print 'Not all parameters are set'
        print_usage()
        exit(-1)

    if not os.path.exists(crash):
        os.mkdir(crash)


    if terminal == False:
        
        # first analyze conf files
        matches = FuzzingLib.analyzeFiles(cdir, conf)
        FuzzingLib.fuzzFile(conf, matches, skip, monitor_func, (exe, conf, crash, int(wait)))

    else:
        user_manual(exe, conf, crash, wait, cdir)

    print('Exitting...')