control 'SV-38929' do
  title 'The system must not have IP tunnels configured.'
  desc 'IP tunneling mechanisms can be used to bypass network filtering.'
  desc 'check', 'Determine if any IP tunnels are configured on the system. 
Check for IP tunnels.
# lstun -a
# ifconfig -a | grep -e gre -e gif -e cti -e sit
If any tunnels are listed, this is a finding.'
  desc 'fix', 'Remove the configuration for any IP tunnels from the system. 

Remove tunnels listed with the lstun command.
#rmtun -t <Tunnel id> -d

Remove the tunneled IP interfaces.
#ifconfig <if name> detach
#rmdev -Rdl <if name>'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-37914r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22547'
  tag rid: 'SV-38929r1_rule'
  tag stig_id: 'GEN007820'
  tag gtitle: 'GEN007820'
  tag fix_id: 'F-33171r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-001551']
  tag nist: ['AC-4']
end
