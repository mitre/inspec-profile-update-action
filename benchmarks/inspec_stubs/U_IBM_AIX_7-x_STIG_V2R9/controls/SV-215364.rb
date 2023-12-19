control 'SV-215364' do
  title 'If AIX server does not host an SNMP agent, the dpid2 daemon must be disabled.'
  desc 'The dpid2 daemon acts as a protocol converter, which enables DPI (SNMP v2) sub-agents, such as hostmibd, to talk to a SNMP v1 agent that follows SNMP MUX protocol.

To prevent attacks this daemon should not be enabled unless there is no alternative.'
  desc 'check', 'From the command prompt, execute the following command: 
# grep "^start[[:blank:]]/usr/sbin/dpid2" /etc/rc.tcpip

If there is any output from the command, this is a finding.'
  desc 'fix', 'In "/etc/rc.tcpip", comment out the "dpid2" entry by running command: 
# chrctcp -d dpid2'
  impact 0.5
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16562r294543_chk'
  tag severity: 'medium'
  tag gid: 'V-215364'
  tag rid: 'SV-215364r508663_rule'
  tag stig_id: 'AIX7-00-003058'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-16560r294544_fix'
  tag 'documentable'
  tag legacy: ['SV-101453', 'V-91355']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
