control 'SV-218684' do
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
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-20159r562933_chk'
  tag severity: 'medium'
  tag gid: 'V-218684'
  tag rid: 'SV-218684r603259_rule'
  tag stig_id: 'GEN007820'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-20157r562934_fix'
  tag 'documentable'
  tag legacy: ['V-22547', 'SV-63413']
  tag cci: ['CCI-000381', 'CCI-001551']
  tag nist: ['CM-7 a', 'AC-4']
end
