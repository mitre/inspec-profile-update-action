control 'SV-26079' do
  title 'Proxy ARP must not be enabled on the system.'
  desc 'Proxy ARP allows a system to respond to ARP requests on one interface on behalf of hosts connected to another interface.  If this function is enabled when not required, addressing information may be leaked between the attached network segments.'
  desc 'check', 'Determine if the system has proxy ARP enabled.  If so, this is a finding.'
  desc 'fix', 'Disable proxy ARP on the system.'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-30043r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22415'
  tag rid: 'SV-26079r1_rule'
  tag stig_id: 'GEN003608'
  tag gtitle: 'GEN003608'
  tag fix_id: 'F-26877r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-001551']
  tag nist: ['AC-4']
end
