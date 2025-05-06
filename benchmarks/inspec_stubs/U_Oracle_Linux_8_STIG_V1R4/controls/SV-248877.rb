control 'SV-248877' do
  title 'OL 8 must not send Internet Control Message Protocol (ICMP) redirects.'
  desc %q(ICMP redirect messages are used by routers to inform hosts that a more direct route exists for a particular destination. These messages contain information from the system's route table, possibly revealing portions of the network topology. 
 
There are notable differences between Internet Protocol version 4 (IPv4) and Internet Protocol version 6 (IPv6). There is only a directive to disable sending of IPv4 redirected packets. Refer to RFC4294 for an explanation of "IPv6 Node Requirements", which resulted in this difference between IPv4 and IPv6.

The sysctl --system command will load settings from all system configuration files. All configuration files are sorted by their filename in lexicographic order, regardless of which of the directories they reside in. If multiple files specify the same option, the entry in the file with the lexicographically latest name will take precedence. Files are read from directories in the following list from top to bottom. Once a file of a given filename is loaded, any file of the same name in subsequent directories is ignored.
/etc/sysctl.d/*.conf
/run/sysctl.d/*.conf
/usr/local/lib/sysctl.d/*.conf
/usr/lib/sysctl.d/*.conf
/lib/sysctl.d/*.conf
/etc/sysctl.conf)
  desc 'check', 'Verify OL 8 does not send IPv4 ICMP redirect messages.

Check the value of the "all send_redirects" variables with the following command:

$ sudo sysctl net.ipv4.conf.all.send_redirects

net.ipv4.conf.all.send_redirects = 0

If the returned line does not have a value of "0" or a line is not returned, this is a finding.

Check that the configuration files are present to enable this network parameter.

$ sudo grep -r net.ipv4.conf.all.send_redirects /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf /etc/sysctl.d/*.conf

/etc/sysctl.d/99-sysctl.conf: net.ipv4.conf.all.send_redirects = 0

If "net.ipv4.conf.all.send_redirects" is not set to "0", is missing or commented out, this is a finding.

If conflicting results are returned, this is a finding.'
  desc 'fix', %q(Configure OL 8 to not allow interfaces to perform IPv4 ICMP redirects with the following command:

$ sudo sysctl -w net.ipv4.conf.all.send_redirects=0

Remove any configurations that conflict with the above from the following locations: 
/run/sysctl.d/*.conf
/usr/local/lib/sysctl.d/*.conf
/usr/lib/sysctl.d/*.conf
/lib/sysctl.d/*.conf
/etc/sysctl.conf
/etc/sysctl.d/*.conf

If "0" is not the system's default value, add or update the following line in "/etc/sysctl.conf" or in the appropriate file under "/etc/sysctl.d":

net.ipv4.conf.all.send_redirects=0)
  impact 0.5
  ref 'DPMS Target Oracle Linux 8'
  tag check_id: 'C-52311r833251_chk'
  tag severity: 'medium'
  tag gid: 'V-248877'
  tag rid: 'SV-248877r858655_rule'
  tag stig_id: 'OL08-00-040220'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-52265r858654_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
