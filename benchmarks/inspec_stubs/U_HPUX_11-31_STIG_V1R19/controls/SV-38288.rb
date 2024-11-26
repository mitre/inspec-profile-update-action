control 'SV-38288' do
  title 'The .Xauthority utility must only permit access to authorized hosts.'
  desc "If unauthorized clients are permitted access to the X server, the user's X session may be compromised."
  desc 'check', 'Verify the X window system access is limited to authorized clients.
# xauth
# xauth> list

Ask the SA if the clients listed are authorized. If any are not, this is a finding.'
  desc 'fix', 'Remove unauthorized clients from the xauth configuration.
# xauth remove <display name>'
  impact 0.5
  ref 'DPMS Target HP-UX 11.31'
  tag check_id: 'C-36603r1_chk'
  tag severity: 'medium'
  tag gid: 'V-12017'
  tag rid: 'SV-38288r1_rule'
  tag stig_id: 'GEN005240'
  tag gtitle: 'GEN005240'
  tag fix_id: 'F-31970r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECCD-1, ECCD-2'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
