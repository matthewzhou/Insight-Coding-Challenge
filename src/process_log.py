from helper_functions import *
import sys
import time

def main(argv):
    starttotal = time.time()
    log = argv[1] #input log txt filepath
    warning = {}
    blocked = {}
    output = []
    ips = {}
    requests = {}
    dates = []
    sample = []
    count = 0
    errorlog = []
    
    try:    #if filepath is invalid, throws an OSError.errno2 exception
        f = open(log,'r', encoding = 'Latin-1')
        while True:
            count += 1 #iterator that logs line count in case of decoding errors
            try:
                line = f.readline()
                if line == '':  #breaks loop when no more new lines
                    break
                ips, requests, dates, blocked, warning, output = process_line(line, ips, dates, requests,blocked, warning,output)
                sample.append(line)
            except UnicodeDecodeError:
                #catches feisty decoding errors and logs them for later
                print("Unicode Decode Error at line {}".format(count))
                errorlog = log_error(errorlog)
 
        f.close()
        start = time.time()
        temp1, temp2, temp3 = find_features(ips, requests,dates)
        print("Feature Execution took " + str(time.time()-start) + " seconds")  
     
        filepath = argv[2]
        to_file(temp1, 1, filepath)
        filepath = argv[3]
        to_file(temp2, 0, filepath)
        filepath = argv[4]
        to_file(temp3, 1, filepath)
        filepath = argv[5]
        to_file(output, 0, filepath)

        """
        Remove comment section to generate an error log txt file at specified
        destination filepath
        #Generate errors log at defined filepath
        filepath = 'SPECIFIED_FILEPATH.txt'
        to_file(errorlog, 1,filepath)
        """
        
        print("Output file created in log_output folder...")
        print("Overall Execution took " + str(time.time()-starttotal) + " seconds")

    except OSError as e:
        if e.errno == 2: # suppress "No such file or directory" error
            errorlog = log_error(errorlog)
            print("Invalid Filepath Input")
     
if __name__ == "__main__":
    main(sys.argv)
    
