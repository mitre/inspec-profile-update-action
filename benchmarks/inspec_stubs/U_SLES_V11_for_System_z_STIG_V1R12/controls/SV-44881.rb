control 'SV-44881' do
  title 'The system must require at least eight characters be changed between the old and new passwords during a password change.'
  desc 'To ensure password changes are effective in their goals, the system must ensure that old and new passwords have significant differences.  Without significant changes, new passwords may be easily guessed based on the value of a previously compromised password.'
  desc 'check', 'Check /etc/pam.d/common-{auth,account,password,session} for a ‘difok’ parameter on the pam_cracklib.so line. 

Procedure:
# grep difok /etc/pam.d/common-{auth,account,password,session}
If difok is not present, or has a value less than 8, this is a finding.

Check for common-password inclusions.
# grep -c common-password /etc/pam.d/*

If the common-password file is included anywhere
# grep difok /etc/pam.d/common-password 

If common-password is included anywhere and difok is not present, or has a value less than 8, this is a finding.

Ensure the passwd command uses the common-password settings.
# grep common-password /etc/pam.d/passwd
If a line "password include common-password" is not found then the password checks in common-password will not be applied to new passwords and this is a finding.'
  desc 'fix', 'Edit /etc/pam.d/common-password and add or edit a pam_cracklib.so entry with a difok parameter set equal to or greater than 8.'
  impact 0.5
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-42335r3_chk'
  tag severity: 'medium'
  tag gid: 'V-22306'
  tag rid: 'SV-44881r2_rule'
  tag stig_id: 'GEN000750'
  tag gtitle: 'GEN000750'
  tag fix_id: 'F-38313r3_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000195']
  tag nist: ['IA-5 (1) (b)']
end
