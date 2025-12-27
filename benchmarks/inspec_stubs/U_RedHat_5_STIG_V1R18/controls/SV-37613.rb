control 'SV-37613' do
  title 'The system must not have IP tunnels configured.'
  desc 'IP tunneling mechanisms can be used to bypass network filtering.'
  desc 'check', 'Check for any IP tunnels.
# ip tun list
# ip -6 tun list
If any tunnels are listed, this is a finding.'
  desc 'fix', 'Remove the tunnels.
# ip tun del <tunnel>
Edit system startup scripts to prevent tunnel creation on startup.'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag check_id: 'C-36809r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22547'
  tag rid: 'SV-37613r1_rule'
  tag stig_id: 'GEN007820'
  tag gtitle: 'GEN007820'
  tag fix_id: 'F-31648r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-001551']
  tag nist: ['AC-4']
end
