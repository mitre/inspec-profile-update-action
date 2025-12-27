control 'SV-218575' do
  title 'The .Xauthority utility must only permit access to authorized hosts.'
  desc "If unauthorized clients are permitted access to the X server, a user's X session may be compromised."
  desc 'check', 'Check the X window system access is limited to authorized clients.

Procedure:
# xauth
xauth> list

Ask the SA if the clients listed are authorized. If any are not, this is a finding.'
  desc 'fix', 'Remove unauthorized clients from the xauth configuration.
# xauth remove <display name>'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-20050r555923_chk'
  tag severity: 'medium'
  tag gid: 'V-218575'
  tag rid: 'SV-218575r603259_rule'
  tag stig_id: 'GEN005240'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-20048r555924_fix'
  tag 'documentable'
  tag legacy: ['V-12017', 'SV-63329']
  tag cci: ['CCI-000366', 'CCI-000225']
  tag nist: ['CM-6 b', 'AC-6']
end
