control 'SV-38469' do
  title 'The /etc/passwd file must have mode 0444 or less permissive.'
  desc 'If the passwd file is writable by a group owner or the world, the risk of passwd file compromise is increased. The passwd file contains the list of accounts on the system and associated information.'
  desc 'check', 'Check the mode of the /etc/passwd file.

Procedure:
# ls -lL /etc/passwd

If /etc/passwd has a mode more permissive than 0444, this is a finding.'
  desc 'fix', 'Change the mode of the passwd file to 0444.
# chmod 0444 /etc/passwd

Document all changes.'
  impact 0.5
  ref 'DPMS Target HP-UX 11.31'
  tag check_id: 'C-36331r1_chk'
  tag severity: 'medium'
  tag gid: 'V-798'
  tag rid: 'SV-38469r1_rule'
  tag stig_id: 'GEN001380'
  tag gtitle: 'GEN001380'
  tag fix_id: 'F-31586r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
