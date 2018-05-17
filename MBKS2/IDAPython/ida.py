from idaapi import *

def recWalk(function_ea, level = 1):
	
	"""
	
	Walks around all functions, called from address function_ea
	
	"""
	
	f_start = function_ea
	f_end = FindFuncEnd(function_ea)
	
	visitedLinks.append(f_start)
	
	print '%s Addr = %08x, Func = %s' % ('-' * level, function_ea, GetFunctionName(function_ea))
		
	# For each defined element in the function.
	for head in Heads(f_start, f_end):
    
        # If the element is an instruction
		if isCode(GetFlags(head)):
        
			# Get the references made from the current instruction
			refs = CodeRefsFrom(head, 0)
		
			if refs:
				
				refs = [ x for x in refs if (x not in visitedLinks) and (x < f_start or x > f_end) ]
				
				for r in refs:
					func(r, level + 1)
					
def findPathToFunc(function_ea, func_to_find, visitedLinks):
	
	""" 
	
	Finds a way to function 
	function_ea - address where the search will be started
	
	"""
	
	# print 'Found Addr = %08x, Func = %s' % (function_ea, GetFunctionName(function_ea))
	
	# Found!
	if function_ea == func_to_find:
		return GetFunctionName(function_ea)
	
	f_start = function_ea
	f_end = FindFuncEnd(function_ea)
	
	# Match address as visited to avoid a loop: func1 -> func2 -> func3 -> func1
	visitedLinks.append(f_start)
	
	# For each defined element in the function.
	for head in Heads(f_start, f_end):
    
        # If the element is an instruction
		if isCode(GetFlags(head)):
        
			# Get the references made from the current instruction
			# those can not be local
			refs = CodeRefsFrom(head, 0)
		
			if refs:
				
				res = None
				refs = [ x for x in refs if (x not in visitedLinks) and (x < f_start or x > f_end) ]
				
				for r in refs:
					
					res = findPathToFunc(r, func_to_find, visitedLinks)
					if res is not None:
						res = GetFunctionName(function_ea) + ' -> ' + res
						return res
					
	return None
 
def trace(function_ea, func_to_find):
	visitedLinks = []
	return findPathToFunc(function_ea, func_to_find, visitedLinks)
 
def printCallSource(addr):
	
	print 'Function [%s] %s is called from:' % (hex(addr), GetFunctionName(addr))
	
	refs = CodeRefsTo(addr, 0)
	for r in refs:		
		print "[%s] %s" % (hex(r), GetFunctionName(r))
	print '\n' 
	
			
inputFunctions = (

	# stdin
	'gets',
	'scanf',
	'getchar',
	
	# file
	'fgetc',
	'getc',
	'fread',
	'fgets',
	'fscanf'
)

unsafeFunctions = (

	'memset',
	'memcpy',
	'memmove',
	'strcpy',
	'strcat',
    
	'sprintf',
	'vsprintf',
	'sscanf',
    
	'malloc',
	'calloc',
	'realloc',
	'free'
)


def listFunctions(ea):

	"""
	
	From function list chose those are in 
	tuples unsafeFunctions and inputFunctions
	
	"""

	inputFuncMap = {}
	unsafeFuncMap = {}

	# Loop through all the functions
	for function_ea in Functions(SegStart(ea), SegEnd(ea)):
		
		funcName = GetFunctionName(function_ea)
		funcAddr = function_ea
		
		if funcName in inputFunctions:
			inputFuncMap[funcName] = funcAddr
		
		elif funcName in unsafeFunctions:
			unsafeFuncMap[funcName] = funcAddr
			
	return inputFuncMap, unsafeFuncMap

	
def commonTrace(ea, addr_from, addr_to):

	""" finds common traces for functions """

	visitedLinks = trace(ea, addr_to)
	
	if visitedLinks is None:
		return None, None

	visited = visitedLinks.split(' -> ')
	
	s1 = None
	s2 = None
	
	for v in reversed(visited):
		
		s1 = trace(LocByName(v), addr_from)
		s2 = trace(LocByName(v), addr_to)
		
		if s1 is not None and s2 is not None:
			return s1, s2

	return None, None
				
			
# start here
	
# Wait until IDA has done all the analysis tasks.
# If loaded in batch mode, the script will be run before
# everything is finished, so the script will explicitly
# wait until the autoanalysis is done.
autoWait()
ea = ScreenEA()

print 'Script start'

input, unsafe = listFunctions(ea)

print '-' * 60
print 'Input functions:'
for e in input.values():
	printCallSource(e)

print '-' * 60
print 'Unsafe functions:'
for e in unsafe.values():
	printCallSource(e)	

print '-' * 60
print 'Traces:'

for name_i, addr_i in input.items():
	for name_u, addr_u in unsafe.items():

		s1, s2 = commonTrace(ea, addr_i, addr_u)
		
		if s1 is None or s2 is None:
			continue
			
		print '-' * 20
		print 'from input func %s to unsafe func %s:' % (name_i, name_u)
		print s1
		print s2

print 'Script end'