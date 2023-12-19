control 'SV-227873' do
  title 'The .Xauthority utility must only permit access to authorized hosts.'
  desc "If unauthorized clients are permitted access to the X server, a user's X session may be compromised."
  desc 'check', 'Check the X Window system access is limited to authorized clients.

Procedure:
# xauth
xauth> list

Ask the SA if the clients listed are authorized.  If any are not, this is a finding.'
  desc 'fix', 'Remove unauthorized clients from the xauth configuration.
# xauth remove <display name>'
  impact 0.5
  ref 'DPMS Target Solaris 10 X86'
  tag check_id: 'C-30035r490015_chk'
  tag severity: 'medium'
  tag gid: 'V-227873'
  tag rid: 'SV-227873r603266_rule'
  tag stig_id: 'GEN005240'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-30023r490016_fix'
  tag 'documentable'
  tag legacy: ['V-12017', 'SV-12518']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
