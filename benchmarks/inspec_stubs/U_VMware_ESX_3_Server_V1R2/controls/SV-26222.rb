control 'SV-26222' do
  title 'The system must not have IP tunnels configured.'
  desc 'IP tunneling mechanisms can be used to bypass network filtering.'
  desc 'check', 'Determine if any IP tunnels are configured on the system.  If any are found, this is a finding.'
  desc 'fix', 'Remove the configuration for any IP tunnels from the system.'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-29303r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22547'
  tag rid: 'SV-26222r1_rule'
  tag stig_id: 'GEN007820'
  tag gtitle: 'GEN007820'
  tag fix_id: 'F-26335r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-001551']
  tag nist: ['AC-4']
end
