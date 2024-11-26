control 'SV-45986' do
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
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-43267r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22547'
  tag rid: 'SV-45986r1_rule'
  tag stig_id: 'GEN007820'
  tag gtitle: 'GEN007820'
  tag fix_id: 'F-39350r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-001551']
  tag nist: ['AC-4']
end
