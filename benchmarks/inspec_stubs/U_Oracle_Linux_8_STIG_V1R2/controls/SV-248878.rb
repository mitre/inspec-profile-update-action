control 'SV-248878' do
  title 'OL 8 must not respond to Internet Control Message Protocol (ICMP) echoes sent to a broadcast address.'
  desc 'Responding to broadcast ICMP echoes facilitates network mapping and provides a vector for amplification attacks. 
 
There are notable differences between Internet Protocol version 4 (IPv4) and Internet Protocol version 6 (IPv6). IPv6 does not implement the same method of broadcast as IPv4. Instead, IPv6 uses multicast addressing to the all-hosts multicast group. Refer to RFC4294 for an explanation of "IPv6 Node Requirements", which resulted in this difference between IPv4 and IPv6.

The sysctl --system command will load settings from all system configuration files. All configuration files are sorted by their filename in lexicographic order, regardless of which of the directories they reside in. If multiple files specify the same option, the entry in the file with the lexicographically latest name will take precedence. Files are read from directories in the following list from top to bottom. Once a file of a given filename is loaded, any file of the same name in subsequent directories is ignored.
/etc/sysctl.d/*.conf
/run/sysctl.d/*.conf
/usr/local/lib/sysctl.d/*.conf
/usr/lib/sysctl.d/*.conf
/lib/sysctl.d/*.conf
/etc/sysctl.conf'
  desc 'check', 'Verify OL 8 does not respond to ICMP echoes sent to a broadcast address.

Note: If IPv4 is disabled on the system, this requirement is not applicable.

Check the value of the "icmp_echo_ignore_broadcasts" variable with the following command:

$ sudo sysctl net.ipv4.icmp_echo_ignore_broadcasts

net.ipv4.icmp_echo_ignore_broadcasts = 1

If the returned line does not have a value of "1", a line is not returned, or the retuned line is commented out, this is a finding.

Check that the configuration files are present to enable this network parameter.

$ sudo grep -r net.ipv4.icmp_echo_ignore_broadcasts /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf /etc/sysctl.d/*.conf

/etc/sysctl.d/99-sysctl.conf: net.ipv4.icmp_echo_ignore_broadcasts = 1

If "net.ipv4.icmp_echo_ignore_broadcasts" is not set to "1", is missing or commented out, this is a finding.

If results are returned from more than one file location, this is a finding.'
  desc 'fix', %q(Configure OL 8 to not respond to IPv4 ICMP echoes sent to a broadcast address with the following command: 
 
$ sudo sysctl -w net.ipv4.icmp_echo_ignore_broadcasts=1 
 
If "1" is not the system's default value, add or update the following line in "/etc/sysctl.conf" or in the appropriate file under "/etc/sysctl.d": 
 
net.ipv4.icmp_echo_ignore_broadcasts=1)
  impact 0.5
  ref 'DPMS Target Oracle Linux 8'
  tag check_id: 'C-52312r818709_chk'
  tag severity: 'medium'
  tag gid: 'V-248878'
  tag rid: 'SV-248878r818710_rule'
  tag stig_id: 'OL08-00-040230'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-52266r780199_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
