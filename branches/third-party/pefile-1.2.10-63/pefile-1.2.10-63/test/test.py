import os
os.sys.path.insert(0, os.environ.get('PEFILE_DIR', '/Users/ero/Devel/pefile'))
import pefile
import time
import sha


def log(s):
    os.sys.stderr.write('> %s \n' % s)
    os.sys.stderr.flush()


def log_results(logfile, s):
    logfile.write('%s\n' % s)
    logfile.flush()
    

def get_time_delta_string(tm_start):

    tm_delta = time.time() - tm_start

    tm_delta_tup = [t-z for (t,z) in zip( time.localtime(tm_delta), time.localtime(0) )]

    tm_delta_str = '%02d:%02d:%02d.%03d' % (
        tm_delta_tup[3], tm_delta_tup[4],
        tm_delta_tup[5], 1000*(tm_delta-long(tm_delta)))

    return tm_delta_str

def main(python_version):
    """The argument should be a string of the form
    
    "Python2.3" or "Python2.5"
    """
    
    date = time.strftime('%Y%m%d')
    
    logfile = file('test-%s-%s-%s.txt' % (
        pefile.__version__, date, python_version), 'w+b')
    
    log('<<<<<--------------------------')
    log('testing pefile version: %s on %s with %s' % (
        pefile.__version__,
        date,
        python_version ) )
    
    tm_start = time.time()
    
    for dirpath, dirnames, filenames in os.walk('./test_files'):
    
        for filename in filenames:

            if filename.endswith('.dmp'):
                continue
        
            filename = os.path.join(dirpath, filename)
            log('Processing [%s]' % filename)
            try:
                pe = pefile.PE(filename)
                
                # Get data from file
                #
                f = file(filename, 'rb')
                data = f.read()
                f.close()
                
                # Hash it
                #
                sha1hash = sha.new(data).hexdigest()
                
                # And compare it to the hash of the data to be
                # written
                #
                new_sha1hash = sha.new(pe.write()).hexdigest()
                
                if sha1hash != new_sha1hash:
                    log('Hashes differ for [%s]: %s,%s' % (
                        filename, sha1hash, new_sha1hash) )
                        
                    new_sha1hash = sha.new(pe.write()[:len(data)]).hexdigest()
                    if sha1hash != new_sha1hash:
                        log('Hashes differ again!! for [%s]: %s,%s' % (
                            filename, sha1hash, new_sha1hash) )
                    else:
                        log('But hashes are the same if the output data is cut down to the same length as that of the input file')
                    
                
                log_results(logfile, '-------------------[%s]' % filename)
                log_results(logfile, pe.dump_info())
                pe.show_warnings()
            except pefile.PEFormatError, excp:
                log('Error parsing file')
        
    timing = 'Test run finished. Elapsed time: %s' % get_time_delta_string(tm_start)
    log_results(logfile,  timing)
    log( timing )
    log('-------------------------->>>>>')
    
    logfile.close()
            
            
if __name__ == '__main__':
    if len(os.sys.argv)<2:
        print 'Not enough arguments. Usage: %s PythonVersionString' % os.sys.argv[0]
        os.sys.exit(1)
        
    main(os.sys.argv[1])
    
