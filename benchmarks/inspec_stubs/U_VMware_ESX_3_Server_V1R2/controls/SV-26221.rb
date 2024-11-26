control 'SV-26221' do
  title 'The system must not have Teredo enabled.'
  desc 'Teredo is an IPv6 transition mechanism involving tunneling IPv6 packets encapsulated in IPv4 packets. Unauthorized tunneling may circumvent network security.'
  desc 'check', 'Determine if any software providing Teredo is installed on the system.  If so, this is a finding.'
  desc 'fix', 'Uninstall the Teredo software from the system.'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-29302r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22546'
  tag rid: 'SV-26221r1_rule'
  tag stig_id: 'GEN007800'
  tag gtitle: 'GEN007800'
  tag fix_id: 'F-26334r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-001551']
  tag nist: ['AC-4']
end
