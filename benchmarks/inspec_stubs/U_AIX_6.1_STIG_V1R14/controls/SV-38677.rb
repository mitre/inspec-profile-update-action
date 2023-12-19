control 'SV-38677' do
  title 'The system must require at least eight characters be changed between the old and new passwords during a password change.'
  desc 'To ensure password changes are effective in their goals, the system must ensure old and new passwords have significant differences. Without significant changes, new passwords may be easily guessed based on the value of a previously compromised password.'
  desc 'check', "Check the value of the mindiff parameter.
Procedure:
#lsuser -a mindiff ALL
If any user's mindiff is less than 8,  this is a finding."
  desc 'fix', 'Use the chsec command to change mindiff to 8.

# chsec -f /etc/security/user -s default -a mindiff=8

# chuser mindiff=8 < user id >'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-36906r2_chk'
  tag severity: 'medium'
  tag gid: 'V-22306'
  tag rid: 'SV-38677r2_rule'
  tag stig_id: 'GEN000750'
  tag gtitle: 'GEN000750'
  tag fix_id: 'F-32075r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000195']
  tag nist: ['IA-5 (1) (b)']
end
