control 'SV-44884' do
  title 'The system must prohibit the reuse of passwords within five iterations.'
  desc "If a user, or root, used the same password continuously or was allowed to change it back shortly after being forced to change it to something else, it would provide a potential intruder with the opportunity to keep guessing at one user's password until it was guessed correctly."
  desc 'check', '# pam-config -q --pwhistory
If the result is not’ password: remember=5’ or higher, then this is a finding.

# ls /etc/security/opasswd
If /etc/security/opasswd does not exist, then this is a finding.

# grep password /etc/pam.d/common-password| grep pam_pwhistory.so | grep remember
If the "remember" option in /etc/pam.d/common-password is not 5 or greater, this is a finding.'
  desc 'fix', 'Create the password history file.
# touch /etc/security/opasswd
# chown root:root /etc/security/opasswd
# chmod 0600 /etc/security/opasswd

Configure pam to use password history.
# pam-config -a --pwhistory
# pam-config -a --pwhistory-remember=5'
  impact 0.5
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-42338r1_chk'
  tag severity: 'medium'
  tag gid: 'V-4084'
  tag rid: 'SV-44884r1_rule'
  tag stig_id: 'GEN000800'
  tag gtitle: 'GEN000800'
  tag fix_id: 'F-38316r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000200']
  tag nist: ['IA-5 (1) (e)']
end
