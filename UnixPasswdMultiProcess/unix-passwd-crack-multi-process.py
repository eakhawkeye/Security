#!/usr/bin/python2.7
# 
# Unix Dictionary Password Cracker
#
# by: EakHawkEye
# Inspired from Violent Python
#
# Password File Format (min): username:passwordhash
# Dictionary File Format: one word per line
#
# --- Credits ---
# Line Count (bufcount): 	http://stackoverflow.com/a/850962
# Time Calculation: 		http://stackoverflow.com/a/5998359
# Time Conversion: 			http://stackoverflow.com/a/175576
# Multiprocess terminate:	http://stackoverflow.com/a/36962624
# Signal Information:		http://www.linuxjournal.com/article/3946
#



##########
# IMPORT #
##########
import crypt
import multiprocessing as mp
import sys, getopt, time
import signal



#############
# FUNCTIONS #
#############
def catch_signal(signal, frame):
	'''
	Simple function to cratch ^c
	Return: nothing
	'''
	print "[*] QUIT: User pressed ^c. Shutting down processes"
	if p:
		p.terminate()

	sys.exit(1)


def usage(myscript):
	'''
	Normal script help function
	Return: nothing
	'''
	print myscript + " -p <passwords file> -d <dictionary file> [-t <amount of threads>]"
	sys.exit(2)


def test_file(file_name, permission):
	'''
	Test the ability to open files with permissions
	Return: nothing
	'''
	try:
		f = open(file_name, permission)
		f.close()
	except:
		"[-] ERROR: Unable to open " + str(file_name)
		sys.exit(1)


def current_time_msec():
	'''
	Gives the current epoch time in milliseconds
	Return: integer
	'''
	return int(round(time.time() * 1000))


def calculate_duration_msec(start, end):
	'''
	Pass millisecond values, returns a dictionary of human time
	Return: dictionary of time metric: values
	'''
	total_msec = end - start
	total_sec  = n = total_msec / 1000
	msec       = total_msec - ( total_sec * 1000 )
	seconds    = n % 60
	n /= 60
	minutes    = n % 60
	n /= 60
	hours      = n % 24
	n /= 24
	days       = n

	return { 'msec': str(msec), 'seconds': str(seconds), 'minutes': str(minutes), 'hours': str(hours), 'days': str(days) }


def count_lines(file_name):
	'''
	Fast method for counting lines in a file
	Return: integer of total number of lines
	'''
	f = open(file_name, 'r')                 
	num_lines = 0
	buf_size = 1024 * 1024
	read_f = f.read

	buf = read_f(buf_size)
	while buf:
		num_lines += buf.count('\n')
		buf = read_f(buf_size)
	
	f.close()
	return num_lines


def get_line_ranges(total_count, user_max_threads):
	'''
	Calulate the processing ranges based on line numbers
	Return: dictionary of start/stop ranges per itration
	'''
	dct        = {}
	line_chunk = total_count / user_max_threads
	for i in range(user_max_threads):
		name       = 'iter' + str(i)
		my_start   = (i * line_chunk) + 1
		my_end     = (i + 1) * line_chunk
		if (i + 1) == user_max_threads:
			my_end = total_count
		dct[name]={'start': my_start, 'end': my_end}
	
	return dct


def get_user(line):
	'''
	Parse the username from the line
	Return: string of the username from the text entry
	'''
	return line.split(':')[0]


def get_crypt(line):
	'''
	Get the hash from the entire line entry
	Return: string ($type$salt$encrypted_password)
	'''
	return line.split(':')[1].strip(' ').strip('\n')


def get_salt(cryptPass):
	'''
	Get the salt from the hash line passed
	Return: string
	'''
	if cryptPass.startswith('$'):
		# password: $6$45678910$...
		salt = cryptPass[0:12]
	else:
		# password: ABCDEFGHIJKL
		salt = cryptPass[0:2]

	return salt


def get_dict_word_variant(word):
	'''
	!!! Disabled for now - used in previous iterations !!!
	Generate variations of the word passed
	Return: list
	'''
	return [ word, word.title(), word.upper() ]


def attack_password(cryptPass, salt, dict_file_name, r_start, r_end):
	'''
	Find the password using the salt + dictionary word
	Multiprocessing based off the division of the dictionary by line numbers
	Return: Boolean
	'''
	dictFile = open(dict_file_name, 'r')

	# Enumerate the words...
	for i, word in enumerate(dictFile):
		# ...to determine which this thread will process
		if (i >= r_start) and (i <= r_end):
			word = word.strip('\n')
			cryptWord = crypt.crypt(word, salt)
			# If a match is found, announce, and exit
			if cryptWord == cryptPass:
				print "[+] Found Password: " + word
				dictFile.close()
				return True

	# If we're here, this thread failed to find the word
	#print "[-] Password Not Found."
	dictFile.close()
	return False


def mp_exit(arg):
	'''
	Once a successful return happens, exit the entire pool
	Return: nothing
	'''
	if arg:
		p.terminate()


def main():
	'''
	Main function - the meat, beans, and mashed potatoss
	Outputs: cracked password (hopefully)
	'''
	system_min_threads = 1
	system_max_threads = mp.cpu_count()
	user_max_threads = system_min_threads

	###############
	# [USER INPUT] Process command-line arguments
	if len(sys.argv) < 5:
		usage(sys.argv[0])

	try:
		opts, args = getopt.getopt(sys.argv[1:],"hp:d:t:",["help","passwords=","dictionary=", "threads="])
	except getopt.GetoptError:
		usage(sys.argv[0])

	for opt, arg in opts:
		if opt in ("-h", "--help"):
			usage(sys.argv[0])
		elif opt in ("-p", "--passwords"):
			pass_file_name = arg
		elif opt in ("-d", "--dictionary"):
			dict_file_name = arg
		elif opt in ("-t", "--threads"):
			try:
				# Threads count = current process + user requested. Total must allow for a total of min+1 and max.
				# We don't want to request more threads than the system can handle and we need at least 1.
				user_val = int(arg)
				user_max_threads = (system_max_threads - 1 ) if user_val >= system_max_threads else user_val
				user_max_threads = system_min_threads if user_max_threads < system_min_threads else user_max_threads
			except:
				user_max_threads = system_min_threads
				print "[-] WARN: Threads set to " + str(user_max_threads) + ". (" + str(arg) + " is not a number)"
		else:
			assert False, "unhandled option"

	############
	# [PREPARE] Validate files and prepare arguments
	test_file(pass_file_name, 'r')
	test_file(dict_file_name, 'r')
	dict_line_count = count_lines(dict_file_name)
	dct_ranges = get_line_ranges(dict_line_count, user_max_threads)

	############
	# [PROCESS] Crack the passwords
	passFile = open(pass_file_name, 'r')
	for line in passFile.readlines():

		if ":" in line and not line.startswith("#"):
			user      = get_user(line)
			cryptPass = get_crypt(line)
			salt      = get_salt(cryptPass)

			print "[*] Cracking Password For: " + user + " (" + cryptPass + ")"
			time_start_msec = current_time_msec()

			# Set the multiprocess pool to global for thread interactivity....
			global p 
			p = mp.Pool(user_max_threads)
			signal.signal(signal.SIGINT, catch_signal)
			# ...and build the pool of processes
			for key in dct_ranges.keys():
				p.apply_async(attack_password, args = (cryptPass, salt, dict_file_name, dct_ranges[key]['start'], dct_ranges[key]['end'],), callback=mp_exit)
			p.close()
			p.join()

			time_end_msec = current_time_msec()
			dct_human_dur = calculate_duration_msec(time_start_msec, time_end_msec)
			
			print "time: " + dct_human_dur['days'] + "d " + dct_human_dur['hours'] + ":" + dct_human_dur['minutes'] + ":" + dct_human_dur['seconds'] + "." + dct_human_dur['msec'] + "\n"

	passFile.close()



####################
# RUN, SCRIPT, RUN #
####################
if __name__ == "__main__":
	main()
