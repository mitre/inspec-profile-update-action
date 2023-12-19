control 'SV-37323' do
  title 'The system must prohibit the reuse of passwords within five iterations.'
  desc "If a user, or root, used the same password continuously or was allowed to change it back shortly after being forced to change it to something else, it would provide a potential intruder with the opportunity to keep guessing at one user's password until it was guessed correctly."
  desc 'check', %q(# ls /etc/security/opasswd
If /etc/security/opasswd does not exist, then this is a finding.

# grep password /etc/pam.d/system-auth| egrep '(pam_pwhistory.so|pam_unix.so|pam_cracklib.so)' | grep remember
If the "remember" option in /etc/pam.d/system-auth is not 5 or greater, this is a finding.

Check for system-auth-ac inclusions.
# grep -c system-auth-ac /etc/pam.d/*

If the system-auth-ac file is included anywhere
# more /etc/pam.d/system-auth-ac | grep password | egrep '(pam_pwhistory.so|pam_unix.so|pam_cracklib.so)' | grep remember

If in /etc/pam.d/system-auth-ac is referenced by another file and the "remember" option is not set to 5 or greater this is a finding.)
  desc 'fix', 'Create the password history file.
# touch /etc/security/opasswd
# chown root:root /etc/security/opasswd
# chmod 0600 /etc/security/opasswd

Enable password history.
If /etc/pam.d/system-auth references /etc/pam.d/system-auth-ac refer to the man page for system-auth-ac for a description of how to add options not configurable with authconfig. Edit /etc/pam.d/system-auth to include the remember option on any "password pam_unix" or "password pam_history" lines set to at least 5.'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag check_id: 'C-36015r4_chk'
  tag severity: 'medium'
  tag gid: 'V-4084'
  tag rid: 'SV-37323r3_rule'
  tag stig_id: 'GEN000800'
  tag gtitle: 'GEN000800'
  tag fix_id: 'F-31265r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000200']
  tag nist: ['IA-5 (1) (e)']
end
