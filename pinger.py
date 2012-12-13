import re, socket, time
import pyping
import pickle

# TODO: Write GUI interface in PyQT4 (laughter ensues) for this whole thing
# GUI goes here... i guess

# TODO: Use json or pickle to save & load these collections
# TODO: Capture signal interrupts to ensure saving of collections
def ping_host(dest, udp=False, timeout=1000, packet_size=55):
    is_hostname = None
    if not re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\$', dest):
        try:
            dest = socket.gethostbyname(dest)
        except socket.error as err:
        #            print('Unable to resolve provided hostname "%s" to IP address. %s: "%s"' % (dest, err.errno, err.strerror))
            bad_hosts.append(dest)
            return False
        finally:
            if dest in treat_ip_as_unresolved:
                bad_hosts.append(dest)
                return False

    # Set up "the ping"
    the_ping = pyping.Ping(dest, timeout=timeout, udp=udp, packet_size=packet_size)
    # do it!
    ping_result = the_ping.do()

    # Whats the verdict?
    if ping_result:
        return True
    else:
        return False


class configuration(object):
    def __init__(self):
        def sanitize_max_loops(self, limit):
            if not isinstance(limit, int):
                #raise ValueError("The value for limit is not of type int")
                limit = 0
            # Reset max_loops to 0 if its value is None or less than 0
            # I dont event want to know the mess that would create if not checked
            elif limit < 0:
                limit = 0
            return limit

            # Initialize the config objects we're using for now until we get a gui and argparse implemented
        self.hosts_dict = {'My box': '127.0.0.1', 'Google Public DNS server': '8.8.8.8',
                           'Something invalid': '666.666.666.666',
                           'Something not resolvable': 'goeatacowyouslimyterrier.com'}
        self.bad_hosts = []

        # Sleep between loops (in seconds)
        self.sleep_between_loops = 30

        # Maximum number of loops to perform, 0 = Infinite. None = 0
        #self.max_loops = 0
        self.max_loops = sanitize_max_loops(0)

        # TODO: Get a list of DNS services that resolve on unresolvable addresses to "help" "navigation errors"
        self.treat_ip_as_unresolved = ['67.215.65.132']
        # In anticvipation of json/pickle hosts storage between instances

        # TODO: Remove bad hosts automagically instead of telling the user to do it
        if len(self.bad_hosts) > 0:
            print(
            'The following hosts are invalid: %l however they need to be removed manually.' % ', '.join(bad_hosts))

    def save_object_to_pickle(self, object_to_save, dest_filename, clobber_existing=False):
        if not isinstance(object_to_save,
                          (str, dict, list, int, float, tuple, set, frozenset, pyping.Ping, pyping.Response)):
            raise ValueError("The value for object_to_save is not a type that can be pickled.")
        file_args = None
        if clobber_existing:
            # Overwrite any existing files outright
            file_args = 'wb'
        else:
            # We're appending to the file, not overwriting it outright
            # TODO: Do we need to pickle.load the existing file, add our object (object_to_save = pickle.load(picklefile.txt) + new_obj_to_pickle) or can we just append it to the file with open(file,'wb')? I think the former is most likely
            file_args = 'ab'
        try:
            pickle.dump(object_to_save, open(dest_filename, file_args, None))
        except pickle.PickleError as ex:
            print "An error occurred while attempting to save the provided object. Error: %s - %s" % (
                ex.message, ex.args)
            return False
        except pickle.PicklingError as ex:
            print("An error occurred in the process of saving the provided object to file: %s. Error %s - %s" % (
                dest_filename, ex.message, ex.args))
            return False
        except:
            return False
        else:
            return True

    def load_object_to_pickle(self, file_to_load):
        if not isinstance(file_to_load, (str, file)):
            raise ValueError("The value for file_to_load is not of type str or file.")

        fd = None

        if type(file_to_load) is str:
        # We were provided with a string. Let's load it as a filename
        #        if not os.path.exists(file_to_load):
        #            raise IOError("Provided filename does not exist: %s" % file_to_load)
        #        try:
        #            new_object = pickle.load(open(file_to_load,'rb'))
            fd = open(file_to_load, 'rb', 2048)
        else:
            # We got a file descriptor. Sweet.
            if type(file_to_load) is file:
                fd = file_to_load
            else:
                return False
                raise IOError('Object provided is not file descriptor and is not a file path.')
        try:
            loaded = pickle.load(fd)

        except pickle.PickleError as ex:
            print "An error occurred while attempting to load the provided file. Error: %s - %s" % (ex.message, ex.args)
            return False

        except pickle.PicklingError as ex:
            print("An error occurred in the process of loading the provided object(s) from file. Error %s - %s" % (
                ex.message, ex.args))
            return False

        except:
            return False

        else:
            return loaded


def main():
    # Initialize the configuration
    config = configuration()
    # Reset our loop counter
    total_loops = 0
    # Do the loop-de-loop
    while total_loops <= max_loops:
        for (name, hostname) in config.hosts_dict.iteritems():
            if ping_host(hostname):
                print('Host %s is up.' % name)
            else:
                print('Host %s is down.' % name)
        total_loops + 1
        time.sleep(config.sleep_between_loops)

if __name__ == '__main__':
    main()
