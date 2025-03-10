control 'SV-227961' do
  title 'The system must not have IP tunnels configured.'
  desc 'IP tunneling mechanisms can be used to bypass network filtering.'
  desc 'check', "Check for any IP tunnels.
# ifconfig -a | grep 'ip.*tun'
If any results are returned, this is a finding."
  desc 'fix', 'Disable the tunnels.
# ifconfig <tunnel> down
Remove the startup configuration for the tunnels.
# rm /etc/hostname.<tunnel>'
  impact 0.5
  ref 'DPMS Target Solaris 10 X86'
  tag check_id: 'C-30123r490315_chk'
  tag severity: 'medium'
  tag gid: 'V-227961'
  tag rid: 'SV-227961r603266_rule'
  tag stig_id: 'GEN007820'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-30111r490316_fix'
  tag 'documentable'
  tag legacy: ['V-22547', 'SV-26927']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
