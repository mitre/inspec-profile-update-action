control 'SV-248879' do
  title 'OL 8 must not forward IPv4 source-routed packets.'
  desc 'Source-routed packets allow the source of the packet to suggest that routers forward the packet along a different path than configured on the router, which can be used to bypass network security measures. This requirement applies only to the forwarding of source-routed traffic, such as when forwarding is enabled and the system is functioning as a router.

The sysctl --system command will load settings from all system configuration files. All configuration files are sorted by their filename in lexicographic order, regardless of which of the directories they reside in. If multiple files specify the same option, the entry in the file with the lexicographically latest name will take precedence. Files are read from directories in the following list from top to bottom. Once a file of a given filename is loaded, any file of the same name in subsequent directories is ignored.
/etc/sysctl.d/*.conf
/run/sysctl.d/*.conf
/usr/local/lib/sysctl.d/*.conf
/usr/lib/sysctl.d/*.conf
/lib/sysctl.d/*.conf
/etc/sysctl.conf'
  desc 'check', 'Verify OL 8 does not accept IPv4 source-routed packets.

Check the value of the accept source route variable with the following command:

$ sudo sysctl net.ipv4.conf.all.accept_source_route

net.ipv4.conf.all.accept_source_route = 0

If the returned line does not have a value of "0", a line is not returned, or the line is commented out, this is a finding.

Check that the configuration files are present to enable this network parameter.

$ sudo grep -r net.ipv4.conf.all.accept_source_route /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf /etc/sysctl.d/*.conf

/etc/sysctl.d/99-sysctl.conf: net.ipv4.conf.all.accept_source_route = 0

If "net.ipv4.conf.all.accept_source_route" is not set to "0", is missing or commented out, this is a finding.

If conflicting results are returned, this is a finding.'
  desc 'fix', %q(Configure OL 8 to not forward IPv4 source-routed packets with the following command:

$ sudo sysctl -w net.ipv4.conf.all.accept_source_route=0

Remove any configurations that conflict with the above from the following locations: 
/run/sysctl.d/*.conf
/usr/local/lib/sysctl.d/*.conf
/usr/lib/sysctl.d/*.conf
/lib/sysctl.d/*.conf
/etc/sysctl.conf
/etc/sysctl.d/*.conf

If "0" is not the system's all value then add or update the following line in the appropriate file under "/etc/sysctl.d":

net.ipv4.conf.all.accept_source_route=0)
  impact 0.5
  ref 'DPMS Target Oracle Linux 8'
  tag check_id: 'C-52313r833255_chk'
  tag severity: 'medium'
  tag gid: 'V-248879'
  tag rid: 'SV-248879r858659_rule'
  tag stig_id: 'OL08-00-040239'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-52267r858658_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
