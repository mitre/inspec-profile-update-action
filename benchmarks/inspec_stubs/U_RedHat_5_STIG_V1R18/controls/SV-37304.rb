control 'SV-37304' do
  title 'The system must require at least eight characters be changed between the old and new passwords during a password change.'
  desc 'To ensure password changes are effective in their goals, the system must ensure that old and new passwords have significant differences.  Without significant changes, new passwords may be easily guessed based on the value of a previously compromised password.'
  desc 'check', 'Check /etc/pam.d/system-auth for a pam_cracklib parameter difok.

Procedure:
# grep difok /etc/pam.d/system-auth
If difok is not present, or has a value less than 8, this is a finding.

Check for system-auth-ac inclusions.
# grep -c system-auth-ac /etc/pam.d/*

If the system-auth-ac file is included anywhere
# more /etc/pam.d/system-auth-ac | grep difok

If system-auth-ac is included anywhere and difok is not present, or has a value less than 8, this is a finding.

Ensure the passwd command uses the system-auth settings.
# grep system-auth /etc/pam.d/passwd
If a line "password include system-auth" is not found then the password checks in system-auth will not be applied to new passwords and this is a finding.'
  desc 'fix', 'If /etc/pam.d/system-auth references /etc/pam.d/system-auth-ac refer to the man page for system-auth-ac for a description of how to add options not configurable with authconfig. Edit /etc/pam.d/system-auth and add or edit a pam_cracklib entry with an difok parameter set equal to or greater than 8.'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag check_id: 'C-35999r3_chk'
  tag severity: 'medium'
  tag gid: 'V-22306'
  tag rid: 'SV-37304r2_rule'
  tag stig_id: 'GEN000750'
  tag gtitle: 'GEN000750'
  tag fix_id: 'F-31252r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000195']
  tag nist: ['IA-5 (1) (b)']
end
