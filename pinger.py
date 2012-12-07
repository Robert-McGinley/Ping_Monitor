import re, socket, time
import pyping
#fuckfuckfuck
# TODO: Write GUI interface in PyQT4 (laughter ensues) for this whole thing

# TODO: Use json or pickle to save & load these collections
# TODO: Capture signal interrupts to ensure saving of collections
hosts_dict = {'My box': '127.0.0.1', 'Google Public DNS server': '8.8.8.8', 'Something invalid': '666.666.666.666',
              'Something not resolvable': 'goeatacowyouslimyterrier.com'}
bad_hosts = []

# Sleep between loops (in seconds)
sleep_between_loops = 30

# Maximum number of loops to perform, 0 = Infinite. None = 0
max_loops = 0

# TODO: Get a list of DNS services that resolve on unresolvable addresses to "help" "navigation errors"
treat_ip_as_unresolved = ['67.215.65.132']

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

# Reset max_loops to 0 if its value is None or less than 0
# I dont event want to know the mess that would create if not checked
if max_loops is None or max_loops < 0:
    max_loops = 0

# In anticvipation of json/pickle hosts storage between instances
# TODO: Remove bad hosts automagically
if len(bad_hosts) > 0:
    print('The following hosts are invalid: %l however they need to be removed manually.' % ', '.join(bad_hosts))


# Reset our loop counter
total_loops = 0
# Do the loop-de-loop
while total_loops <= max_loops:
    for (name, hostname) in hosts_dict.iteritems():
        if ping_host(hostname):
            print('Host %s is up.' % name)
        else:
            print('Host %s is down.' % name)
    total_loops + 1
    time.sleep(sleep_between_loops)
