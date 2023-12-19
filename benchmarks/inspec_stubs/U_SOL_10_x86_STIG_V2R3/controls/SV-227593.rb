control 'SV-227593' do
  title 'The system must require at least eight characters be changed between the old and new passwords during a password change.'
  desc 'To ensure password changes are effective in their goals, the system must ensure old and new passwords have significant differences.  Without significant changes, new passwords may be easily guessed based on the value of a previously compromised password.'
  desc 'check', 'Check /etc/default/passwd to verify the MINDIFF setting. 

# grep MINDIFF /etc/default/passwd

If the setting is not present, or is less than 8, this is a finding.'
  desc 'fix', 'Edit /etc/default/passwd and set or add a MINDIFF setting equal to or greater than 8.'
  impact 0.5
  ref 'DPMS Target Solaris 10 X86'
  tag check_id: 'C-29755r488327_chk'
  tag severity: 'medium'
  tag gid: 'V-227593'
  tag rid: 'SV-227593r603266_rule'
  tag stig_id: 'GEN000750'
  tag gtitle: 'SRG-OS-000072'
  tag fix_id: 'F-29743r488328_fix'
  tag 'documentable'
  tag legacy: ['V-22306', 'SV-26324']
  tag cci: ['CCI-000195']
  tag nist: ['IA-5 (1) (b)']
end
