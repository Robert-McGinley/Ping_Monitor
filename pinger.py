import re, time
import pyping
import pickle
from collections import defaultdict as ddict
import netaddr

# TODO: Write GUI interface in PyQT4 (laughter ensues) for this whole thing
# GUI goes here... i guess

# TODO: Use json or pickle to save & load these collections
# TODO: Capture signal interrupts to ensure saving of collections
class configuration(object):
    def __init__(self, default_host_status=None, **kwargs):
        self.regex_hostname_allowed_chars = re.compile(r'(?!-)[A-Z\d-]{1,63}(?<!-)', re.IGNORECASE)
        self.regex_ipv4_addr = re.compile(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')

        def sanitize_max_loops(limit):
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
        # Initialize our status tracking dictionary as a defaultdict
        self.hosts_status_dict = ddict(default_host_status)
        for name, hostname in self.hosts_dict.iteritems():
            self.hosts_status_dict.update(name=None)
            #        print self.hosts_status_dict
        # Initialize list of bad hosts that were specified to us
        self.bad_hosts = []

        # Sleep between loops (in seconds)
        self.sleep_between_loops = 30

        # Maximum number of loops to perform, 0 = Infinite. None = 0
        #self.max_loops = 0
        self.max_loops = sanitize_max_loops(0)

        # TODO: Get a list of DNS services that resolve on unresolvable addresses to "help" "navigation errors"
        self.treat_ip_as_unresolved = ['67.215.65.132']

        # TODO: Remove bad hosts automagically instead of telling the user to do it
        if len(self.bad_hosts) > 0:
            print(
                'The following hosts are invalid: %l however they need to be removed manually.' % ', '.join(
                    config.bad_hosts))

    def add_to_bad_hosts(self, bad_host):
        if not isinstance(bad_host, str):
            raise ValueError("The value for bad_hosts is not of type str")
        self.bad_hosts.append(bad_host)
        return True

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

config = configuration()

def is_valid_hostname(hostname):
    if hostname is None:
        return False

    # Remove a trailing dot, if it exists
    if hostname[-1:] == ".":
        hostname = hostname[:-1]

    # Check if it's an IP address, not an actual hostname. Do ip address checks with netaddr
    if re.match(config.regex_ipv4_addr, hostname):
        if not netaddr.valid_ipv4(hostname):
            return False
            #        if not all(0 <= int(x) <= 255 for x in hostname.split('.')):
            #            return False
            #        try:
            #            ghba = socket.gethostbyaddr(hostname)
            #        except:
            #            return False
    else:
        if len(hostname) > 255:
            return False

        # Check if we have valid characters in our hostname
        if not all(config.regex_hostname_allowed_chars.match(x) for x in hostname.split(".")):
            return False

    if hostname in config.treat_ip_as_unresolved:
        config.bad_hosts.append(hostname)
        return False

    return True


def ping_host(dest, udp=False, timeout=1000, packet_size=55):
#
#    if not re.match(config.regex_ipv4_addr, dest):
#        try:
#            dest = socket.gethostbyname(dest)
#        except socket.error as err:
#        #            print('Unable to resolve provided hostname "%s" to IP address. %s: "%s"' % (dest, err.errno, err.strerror))
#            config.bad_hosts.append(dest)
#            return False
#        finally:
##            if config.is_valid_hostname(dest):
##                # Host is bad
##                config.add_to_bad_hosts(dest)
##                return False

    try:
        # Set up "the ping"
        the_ping = pyping.Ping(dest, timeout=timeout, udp=udp, packet_size=packet_size)
        # do it!
        ping_result = the_ping.do()
    except:
        return False
        # Whats the verdict?
    if ping_result:
        return True
    else:
        return False


def main():
    # Check through our hostnames and clean out anything we cant work with.
    temp_hosts = config.hosts_dict.copy()
    for (name, hostname) in temp_hosts.iteritems():
        if not is_valid_hostname(hostname):
            print("Removing bad host: " + hostname)
            config.hosts_dict.pop(name)
            config.bad_hosts.append(hostname)
    del temp_hosts

    # (Re)set our loop counter
    loop_counter = 0
    # Do the loop-de-loop
    while loop_counter <= config.max_loops:
        for (name, hostname) in config.hosts_dict.iteritems():
            # Todo: Figure out what kind of host check to perform
            # Name == Human readable name of the host object
            # hoatname == Proper FQDN or IP address of the host to check
            if ping_host(hostname):
                print('Host %s is up.' % name)
            else:
                print('Host %s is down.' % name)
        loop_counter + 1
        time.sleep(config.sleep_between_loops)


if __name__ == '__main__':
    main()
#else:
#    sys.exit(False)
