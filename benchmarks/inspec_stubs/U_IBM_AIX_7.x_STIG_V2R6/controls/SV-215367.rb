control 'SV-215367' do
  title 'The ndpd-host daemon must be disabled on AIX.'
  desc 'This is the Neighbor Discovery Protocol (NDP) daemon, required in IPv6.

The ndpd-host is the NDP daemon for the server. Unless the server utilizes IPv6, this is not required and should be disabled to prevent attacks.'
  desc 'check', 'If the system is using IPv6, this is Not Applicable.

From the command prompt, execute the following command: 
# grep "^start[[:blank:]]/usr/sbin/ndpd-host" /etc/rc.tcpip

If there is any output from the command, this is a finding.'
  desc 'fix', 'In "/etc/rc.tcpip", comment out the "ndpd-host" entry by running command: 
# chrctcp -d ndpd-host'
  impact 0.5
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16565r808439_chk'
  tag severity: 'medium'
  tag gid: 'V-215367'
  tag rid: 'SV-215367r808440_rule'
  tag stig_id: 'AIX7-00-003062'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-16563r294553_fix'
  tag 'documentable'
  tag legacy: ['SV-101461', 'V-91363']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
