control 'SV-248883' do
  title 'OL 8 must not enable IPv6 packet forwarding unless the system is a router.'
  desc 'Routing protocol daemons are typically used on routers to exchange network topology information with other routers. If this software is used when not required, system network information may be unnecessarily transmitted across the network.

The sysctl --system command will load settings from all system configuration files. All configuration files are sorted by their filename in lexicographic order, regardless of which of the directories they reside in. If multiple files specify the same option, the entry in the file with the lexicographically latest name will take precedence. Files are read from directories in the following list from top to bottom. Once a file of a given filename is loaded, any file of the same name in subsequent directories is ignored.
/etc/sysctl.d/*.conf
/run/sysctl.d/*.conf
/usr/local/lib/sysctl.d/*.conf
/usr/lib/sysctl.d/*.conf
/lib/sysctl.d/*.conf
/etc/sysctl.conf'
  desc 'check', 'Verify OL 8 is not performing IPv6 packet forwarding unless the system is a router.

Note: If IPv6 is disabled on the system, this requirement is Not Applicable.

Determine if IPv6 forwarding is disabled using the following commands:

$ sudo sysctl net.ipv6.conf.all.forwarding

net.ipv6.conf.all.forwarding = 0

If the IPv6 forwarding value is "1" and is not documented with the Information System Security Officer (ISSO) as an operational requirement, this is a finding.

Check that the configuration files are present to enable this network parameter.

$ sudo grep -r net.ipv6.conf.all.forwarding /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf /etc/sysctl.d/*.conf

/etc/sysctl.d/99-sysctl.conf: net.ipv6.conf.all.forwarding = 0

If "net.ipv6.conf.all.forwarding" is not set to "0", is missing or commented out, this is a finding.

If conflicting results are returned, this is a finding.'
  desc 'fix', %q(Configure OL 8 to not allow IPv6 packet forwarding unless the system is a router with the following command:

$ sudo sysctl -w net.ipv6.conf.all.forwarding=0

Remove any configurations that conflict with the above from the following locations: 
/run/sysctl.d/*.conf
/usr/local/lib/sysctl.d/*.conf
/usr/lib/sysctl.d/*.conf
/lib/sysctl.d/*.conf
/etc/sysctl.conf
/etc/sysctl.d/*.conf

If "0" is not the system's default value, add or update the following lines in "/etc/sysctl.conf" or in the appropriate file under "/etc/sysctl.d":

net.ipv6.conf.all.forwarding=0)
  impact 0.5
  ref 'DPMS Target Oracle Linux 8'
  tag check_id: 'C-52317r833265_chk'
  tag severity: 'medium'
  tag gid: 'V-248883'
  tag rid: 'SV-248883r858669_rule'
  tag stig_id: 'OL08-00-040260'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-52271r858668_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
