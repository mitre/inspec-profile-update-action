control 'SV-215368' do
  title 'The ndpd-router must be disabled on AIX.'
  desc 'This manages the Neighbor Discovery Protocol (NDP) for non-kernel activities, required in IPv6.

The ndpd-router manages NDP for non-kernel activities. Unless the server utilizes IPv6, this is not required and should be disabled to prevent attacks.'
  desc 'check', 'From the command prompt, execute the following command: 
# grep "^start[[:blank:]]/usr/sbin/ndpd-router" /etc/rc.tcpip

If there is any output from the command, this is a finding.'
  desc 'fix', 'In "/etc/rc.tcpip", comment out the "ndpd-router" entry by running command: 
# chrctcp -d ndpd-router'
  impact 0.5
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16566r294555_chk'
  tag severity: 'medium'
  tag gid: 'V-215368'
  tag rid: 'SV-215368r508663_rule'
  tag stig_id: 'AIX7-00-003063'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-16564r294556_fix'
  tag 'documentable'
  tag legacy: ['V-91365', 'SV-101463']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
