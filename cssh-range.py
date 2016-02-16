#!/usr/bin/python2

##
# Shorthand for starting cssh (cluster-ssh) on a range of avahi-like hostnames
#
# Copyright (C) 2015 Jonas Hauquier
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
##


import sys
import os
import subprocess
import socket


class AvahiHost(object):
    def __init__(self, hostname, domain='local', protocol="", interface="", description=""):
        self.hostname = hostname
        self.domain = domain
        self.protocol = protocol
        self.interface = interface
        self.description = description

    @property
    def address(self):
        return "%s.%s" % (self.hostname, self.domain)

    @property
    def ip(self):
        try:
            return socket.gethostbyname_ex(self.address)[2][0]
        except:
            return None

    @property
    def base_hostname(self):
        common = self.hostname.rstrip('0123456789')
        if not common.endswith('-'):
            # Not an indexed hostname
            return None
        # Remove the trailing -
        common = common[:-1]
        return common

    @property
    def index(self):
        common = self.hostname.rstrip('0123456789')
        if not common.endswith('-'):
            # Not an indexed hostname
            return ""
        return self.hostname[len(common):]

    def __str__(self):
        return "<AvahiHost %s.%s>" % (self.hostname, self.domain)

    def __repr__(self):
        return self.__str__()

    def __unicode__(self):
        return self.__str__()


def which(filename):
    for path in os.environ["PATH"].split(os.pathsep):
        full_path = os.path.join(path, filename)
        if os.path.exists(full_path):
                return full_path
    return None

def getAvahiHosts():
    hosts = []
    hostnames = dict()
    avahi_browse = which("avahi-browse")
    if not avahi_browse:
        raise RuntimeError("Error: the avahi-browse application is not installed")
        return hosts
    client_list=subprocess.Popen([avahi_browse,"-at"], stdout=subprocess.PIPE)
    client_list.wait()
    for line in client_list.stdout.readlines():
        tokens = line.split()
        _type = tokens[0]
        _if = tokens[1]
        proto = tokens[2]
        hostname = tokens[3]
        domain = tokens[-1]
        desc = ' '.join(tokens[4:-1])  # TODO merges two fields together
        host = AvahiHost(hostname, domain, proto, _if, desc)
        if host.address not in hostnames:
            # Prevent doubles
            # TODO a nicer way is to make a set and implement _eq
            hostnames[host.address] = True
            hosts.append(host)
    return hosts

def ping(hostname):
    ping = which("ping")
    if not ping:
        raise RuntimeError("Error: the ping application is not installed")
    print ("Pinging %s ..." % hostname)
    p = subprocess.Popen([ping, '-c', '1', hostname], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out,err = p.communicate()
    return p.returncode == 0

def discover_hosts_in_range(base_hostname, ping_missing=False, start_idx=None, end_idx=None):
    if not start_idx:
        start_idx = 1
    if not end_idx:
        end_idx = float("inf")

    def _same_basename(host):
        common = host.base_hostname
        return common and common == base_hostname

    hosts = getAvahiHosts()
    hosts = filter(_same_basename, hosts)

    # Sort hosts by index
    hosts = sorted(hosts, key=lambda h: int(h.index))
    result = []
    for h in hosts:
        if int(h.index) >= start_idx and int(h.index) <= end_idx:
            result.append(h)

    if ping_missing:
        result = append_missing_hosts_in_range(result, start_idx, end_idx)
    return result

def append_missing_hosts_in_range(hosts, start_idx, end_idx):
    """
    In an expected range of hosts, ping for missing in-between host ranges
    and add them if they exist. This helps smoothing out temporary sync issues
    with avahi hostname discover, where some entries could be missing.
    """
    END_PADDING = 2  # extra index range to try when no specific end range is given
    # TODO we could also keep trying until a ping returns False

    def _new_address(host, idx):
        return "%s-%s.%s" % (host.base_hostname, idx, host.domain)

    def _new_host(host, idx):
        hostname = "%s-%s" % (host.base_hostname, idx)
        return AvahiHost(hostname, host.domain, host.protocol, host.interface, host.description)

    result = []
    if len(hosts) == 0:
        return []  # No hosts to copy details from

    if end_idx == float('inf'):
        end_idx = int(hosts[-1].index) + END_PADDING

    curr_idx = start_idx
    l_idx = 0
    while l_idx < len(hosts):
        i = int(hosts[l_idx].index)
        while curr_idx < i:
            # Ping for missing in-between hosts
            if ping(_new_address(hosts[l_idx], curr_idx)):
                result.append(_new_host(hosts[l_idx], curr_idx))
                print ("Adding host %s discovered by ping" % result[-1].address)
            curr_idx += 1
        result.append(hosts[l_idx])
        curr_idx = int(hosts[l_idx].index) + 1
        l_idx += 1
    while curr_idx <= end_idx:
        # Fill up hosts until the end of the range
        if ping(_new_address(result[-1], curr_idx)):
            result.append(_new_host(result[-1], curr_idx))
            print ("Adding host %s discovered by ping" % result[-1].address)
        curr_idx += 1

    return result

def clear_known_hosts(hosts):
    ssh_keygen = which('ssh-keygen')
    if not ssh_keygen:
        raise RuntimeError("Error: the ssh-keygen application is not installed")
    known_hosts_file = os.path.expanduser('~/.ssh/known_hosts')

    def forget(address):
        if not address:
            return
        print ("Forgetting known_host key for %s" % address)
        p = subprocess.Popen([ssh_keygen, '-f', known_hosts_file, '-R', address])
        p.communicate()

    for h in hosts:
        forget(h.address)
        forget(h.ip)
    return True

def open_cssh(hosts, user=None):
    if user:
        addresses = ["%s@%s" % (user,h.address) for h in hosts]
    else:
        addresses = [h.address for h in hosts]

    cssh = which('cssh')
    if not cssh:
        raise RuntimeError("Error: the cssh application is not installed")
    p = subprocess.Popen([cssh] + addresses)
    p.communicate()
    print "Connections closed"
    return True

def usage():
    return """
Usage:
cssh-range.py [-h] [<username@>]<hostname_base> [<begin>] [<end>]
  cssh-range takes a hostname_base as argument, which is translated to a range
  of hostnames by appending "-x" where x is an increasing index number.

  hostname_base   The base hostname to use in the range
  username        The username to login to SSH with
  begin           Integer number where the range should begin
  end             Integer number where the range should stop (inclusive)
                  When only one number is specified, it's the end index, begin
                  defaults to 1
                  Not specifying begin and/or end index will use avahi-browse
                  to discover the available range and include all

  -h, --help      Shows this help message
  -l, --list      List hostnames in range only, do not connect
  -c, --clearkeys Clear the ssh known_host keys for the hosts in range
  -p, --ping      Ping to detect missing hostnames in range
"""

def main(args):
    print """Cluster-ssh range  an avahi-backed cluster-ssh connection tool
    Copyright (C) 2015  Jonas Hauquier

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.\n"""

    if '-h' in args or '--help' in args:
        print usage()
        sys.exit(0)

    def _get_hostname_user(hostname_arg):
        if '@' in hostname_arg:
            return hostname_arg.split('@')[:2]
        return (None, hostname_arg)

    list_only = False
    if '-l' in args or '--list' in args:
        list_only = True

    do_clear_known_hosts = False
    if '-c' in args or '--clearkeys' in args:
        do_clear_known_hosts = True

    ping_missing = False
    if "-p" in args or "--ping" in args:
        ping_missing = True

    args = [a for a in args if not a.startswith('-')]

    if len(args) == 0:
        print "No hostname specified"
        print usage()
        sys.exit(-1)
    elif len(args) == 1:
        user, base_hostname = _get_hostname_user(args[0])
        hosts = discover_hosts_in_range(base_hostname, ping_missing)
    elif len(args) == 2:
        user, base_hostname = _get_hostname_user(args[0])
        idx_end = int(args[1])
        hosts = discover_hosts_in_range(base_hostname, ping_missing, None, idx_end)
    else:
        user, base_hostname = _get_hostname_user(args[0])
        idx_start = int(args[1])
        idx_end = int(args[2])
        hosts = discover_hosts_in_range(base_hostname, ping_missing, idx_start, idx_end)

    if len(hosts) == 0:
        print "No hosts found"
        sys.exit(-2)

    if do_clear_known_hosts:
        clear_known_hosts(hosts)

    if list_only:
        print "Hostname listing:\n  %s" % '\n  '.join([h.address for h in hosts])
        sys.exit(0)

    print "Opening ClusterSSH:\n  %s" % '\n  '.join([h.address for h in hosts])
    open_cssh(hosts, user)
    sys.exit(0)

if __name__=="__main__":
    try:
        main(sys.argv[1:])
    except RuntimeError as e:
        print e
        sys.exit(-1)

