control 'SV-215355' do
  title 'The AIX DHCP client must be disabled.'
  desc 'The dhcpcd daemon receives address and configuration information from the DHCP server. DHCP relies on trusting the local network. If the local network is not trusted, then it should not be used.

To prevent remote attacks this daemon should not be enabled unless there is no alternative.

'
  desc 'check', 'If the DHCP client is needed by the system and is documented, this is Not Applicable. 

Determine if the DHCP client is running: 

# ps -ef |grep dhcpcd 

If "dhcpcd" is running, this is a finding.

Verify that DHCP is disabled on startup:

# grep "^start[[:blank:]]/usr/sbin/dhcpcd" /etc/rc.tcpip

If there is any output from the command, this is a finding.'
  desc 'fix', %q(Disable the system's DHCP client. 

In "/etc/rc.tcpip", comment out the "dhcpcd" entry by running command:

# chrctcp -d dhcpcd

Reboot the system to ensure the DHCP client has been disabled fully. 

Configure a static IP for the system, if network connectivity is required.)
  impact 0.5
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16553r294516_chk'
  tag severity: 'medium'
  tag gid: 'V-215355'
  tag rid: 'SV-215355r508663_rule'
  tag stig_id: 'AIX7-00-003049'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-16551r294517_fix'
  tag satisfies: ['SRG-OS-000095-GPOS-00049', 'SRG-OS-000480-GPOS-00227']
  tag 'documentable'
  tag legacy: ['SV-101433', 'V-91335']
  tag cci: ['CCI-000366', 'CCI-000381']
  tag nist: ['CM-6 b', 'CM-7 a']
end
