import difflib
import random
import os

from binascii import unhexlify

def compareTwoLists(list1, list2, mode = False):
    
    """ compare two lists """

    assert(type(list1) == type([]) and type(list2) == type([]))

    matcher = difflib.SequenceMatcher(None, list1, list2)   
    matches = matcher.get_matching_blocks()
    
    if (mode):
        return matches

    else:

        out = []
        for elem in matches:
            out.extend(list1[elem.a : elem.a + elem.size])

        return out

def analyzeFiles(test_dir_path, main_conf_file):
    
    """ compare files in directory """

    print('Analyze start:\n')

    # test directory must contain at least 2 files
    files_in_dir = [f for f in os.listdir(test_dir_path) if os.path.isfile(os.path.join(test_dir_path, f))]
    assert(files_in_dir is not None and len(files_in_dir) > 1)
    
    # print what we founfd in test directory
    for file in files_in_dir:
        print("found file %s" % file)
    
    print("\nStarting comparison...")   
    
    # remove from list element - our conf file
    files_in_dir.remove(main_conf_file)
    
    # read our conf file
    conf_file = open(test_dir_path + '\\' + main_conf_file, 'rb')
    conf_file_info = list(conf_file.read())
    conf_file.close()
    
    matches = list(conf_file_info)
    
    # comparison of conf files
    for file in files_in_dir:
        
        other_conf_file = open(test_dir_path + '\\' + file, 'rb')
        matches = compareTwoLists(matches, list(other_conf_file.read()))
        other_conf_file.close()
    
    matches = compareTwoLists(conf_file_info, matches, True)
      
    print("\nFile has following format:\n")
  
    a = 0
    b = 0
    print('|')
    
    for match in matches:
    
        b = match.a
        
        if (a < b):
            print("|-[various data from %d to %d]" % (a, b))
    
        a = match.a; b = match.a + match.size
    
        if (a < b):
            print("|-[permanent data from %d to %d]" % (a, b))
    
        a = b

    return matches

def changeFileBytes(file, start, data):
  
    """ change bytes beginning from position start
        from beginning of the file. """
    start = int(start)

    file.seek(start)
    file.write(data)
    file.flush()

def insertFileBytes(file, start, data):
    
    """ insert bytes beginning from position start from beginning of the file """

    start = int(start)

    # s - bytearray
    file.seek(0)
    s = file.read()
    s = s[0 : start] + data + s[start : ]

    file.seek(0)
    file.write(s)
    file.flush()

def removeFileBytes(file, start, end):
       
    """ removes bytes beginning from position start to position end """

    start = int(start); end = int(end)

    file.seek(0)
    s = file.read()
    s = s[0 : start] + s[end : ]

    file.seek(0)
    file.truncate()
    file.write(s)
    file.flush()

def getFileBytes(file, start, data_len):

    """ save some bytes from file and keep them """

    start = int(start); data_len = int(data_len)

    file.seek(start)
    s = file.read(data_len)
    return s;

def showFileBytes(file, start, end):                                      

    """ show file bytes from start to end """

    start = int(start); end = int(end)

    bytes = getFileBytes(file, start, end - start)
    print 'Bytes from %d to %d:' % (start, end)
    print '%s' % list(bytes)

def int_to_bytes(val, endianness='big'):
    """
    Use :ref:`string formatting` and :func:`~binascii.unhexlify` to
    convert ``val``, a :func:`long`, to a byte :func:`str`.

    :param long val: The value to pack

    :param str endianness: The endianness of the result. ``'big'`` for
      big-endian, ``'little'`` for little-endian.

    If you want byte- and word-ordering to differ, you're on your own.

    Using :ref:`string formatting` lets us use Python's C innards.
    """

    # one (1) hex digit per four (4) bits
    width = val.bit_length()

    # unhexlify wants an even multiple of eight (8) bits, but we don't
    # want more digits than we need (hence the ternary-ish 'or')
    width += 8 - ((width % 8) or 8)

    # format width specifier: four (4) bits per hex digit
    fmt = '%%0%dx' % (width // 4)

    # prepend zero (0) to the width, to zero-pad the output

    s = unhexlify(fmt % val)

    if endianness == 'little':
        # see http://stackoverflow.com/a/931095/309233
        s = s[::-1]

    return s
 
def fuzzPieceOfFile(file, start, end, elem, func, func_args):

    """ fuzz one piece of file """

    delta = end - start
    elem_len = len(elem)
    
    if (elem_len <= delta):

        for i in range(delta - elem_len + 1):
            
            oldBytes = getFileBytes(file, start + i, elem_len)
            changeFileBytes(file, start + i, elem)
    
            func(func_args)
            changeFileBytes(file, start + i, oldBytes)

def fuzzStaticPieceOfFile(file, start, end, values, func, func_args):

    """ fuzz one piece of file with many values """

    for element in values:
        fuzzPieceOfFile(file, start, end, element, func, func_args)
        
def fuzzDynamicPieceOfFile(file, start, end, value, func, func_args):

    """ fuzz one piece of file by changing the length of data """

    delta = end - start
    trash = int_to_bytes(value)

    # this value must be a single byte
    assert(len(trash) == 1)

    # increasing input data
    for data_inc in range (1, 4):
 
        insertFileBytes(file, start, trash * data_inc * delta)
        #showFileBytes(file, start, end)
        func(func_args)
        removeFileBytes(file, start, start + data_inc * delta)

def empty_func(args):
    pass

def fuzzFile(path, matches, skip_if_more, func = empty_func, func_args = None):

    """ fuzzing all file and check if program using it crashed """

    values = (

        1 * '\x00',
        2 * '\x00',
        4 * '\x00',
        6 * '\x00',
        8 * '\x00',

        1 * '\xFF',
        2 * '\xFF',
        4 * '\xFF',
        6 * '\xFF',
        8 * '\xFF',

        1 * int_to_bytes(0xFFFF/2),
        2 * int_to_bytes(0xFFFF/2),
        1 * int_to_bytes(0xFFFF/2 - 1),
        2 * int_to_bytes(0xFFFF/2 - 1),        
        1 * int_to_bytes(0xFFFF/2 + 1),
        2 * int_to_bytes(0xFFFF/2 + 1)

    )


    file = open(path, 'rb+')

    a = b = 0 
    for match in matches:
    
        b = match.a
        
        if (a < b):

            print("fuzzing a region of various data from %d to %d" % (a, b))
            
            # various data -> vulner: data format, data length
            fill_val = random.randint(ord('A'), ord('Z'))
            fuzzDynamicPieceOfFile(file, a, b, fill_val, func, func_args)

            if (skip_if_more > b - a):
                fuzzStaticPieceOfFile(file, a, b, values, func, func_args)

        a = match.a; b = match.a + match.size
    
        if (a < b):

            if (skip_if_more > b - a):

                # permanent data -> vulner: data format
                print("fuzzing a region of permanent data from %d to %d]" % (a, b))
                fuzzStaticPieceOfFile(file, a, b, values, func, func_args)
    
        a = b

    file.close()
    print('fuzzing regions of file is finished')
