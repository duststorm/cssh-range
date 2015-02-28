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

def getAvahiHosts():
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

    hosts = []
    hostnames = dict()
    if not os.path.exists("/usr/bin/avahi-browse"):
        return hosts
    client_list=subprocess.Popen(["avahi-browse","-at"],stdout=subprocess.PIPE)
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

def discover_hosts_in_range(base_hostname, start_idx=None, end_idx=None):
    if not start_idx:
        start_idx = 1
    if not end_idx:
        end_idx = float("inf")

    def same_basename(host):
        common = host.hostname.rstrip('0123456789')
        if not common.endswith('-'):
            # Not an indexed hostname
            return False
        # Remove the trailing -
        common = common[:-1]
        return common == base_hostname

    hosts = getAvahiHosts()
    hosts = filter(same_basename, hosts)

    # Sort hosts by index
    hosts = sorted(hosts, key=lambda h: int(h.index))
    result = []
    for h in hosts:
        if int(h.index) >= start_idx and int(h.index) <= end_idx:
            result.append(h)
    return result

def open_cssh(hosts, user=None):
    if user:
        addresses = ["%s@%s" % (user,h.address) for h in hosts]
    else:
        addresses = [h.address for h in hosts]
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

    args = [a for a in args if not a.startswith('-')]

    if len(args) == 0:
        print "No hostname specified"
        print usage()
        sys.exit(-1)
    elif len(args) == 1:
        user, base_hostname = _get_hostname_user(args[0])
        hosts = discover_hosts_in_range(base_hostname)
    elif len(args) == 2:
        user, base_hostname = _get_hostname_user(args[0])
        idx_end = int(args[1])
        hosts = discover_hosts_in_range(base_hostname, None, idx_end)
    else:
        user, base_hostname = _get_hostname_user(args[0])
        idx_start = int(args[1])
        idx_end = int(args[2])
        hosts = discover_hosts_in_range(base_hostname, idx_start, idx_end)

    if list_only:
        print "Hostname listing:\n  %s" % '\n  '.join([h.address for h in hosts])
        sys.exit(0)

    print "Opening ClusterSSH:\n  %s" % '\n  '.join([h.address for h in hosts])
    open_cssh(hosts, user)
    sys.exit(0)

if __name__=="__main__":
    main(sys.argv[1:])
