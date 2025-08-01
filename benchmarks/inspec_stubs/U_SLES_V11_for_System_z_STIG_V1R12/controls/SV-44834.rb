control 'SV-44834' do
  title 'The system must disable accounts after three consecutive unsuccessful login attempts.'
  desc 'Disabling accounts after a limited number of unsuccessful login attempts improves protection against password guessing attacks.'
  desc 'check', 'Check the pam_tally configuration.
# more /etc/pam.d/login
Confirm the following line is configured, before the "common-auth” file is included:
auth     required       pam_tally.so deny=3 onerr=fail
# more /etc/pam.d/sshd
Confirm the following line is configured, before the "common-auth” file is included:
auth     required       pam_tally.so deny=3 onerr=fail

If no such line is found, this is a finding.'
  desc 'fix', 'Edit /etc/pam.d/login and/or /etc/pam.d/sshd and add the following line, before the "common-auth" file is included:
auth     required       pam_tally.so deny=3 onerr=fail'
  impact 0.5
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-42305r1_chk'
  tag severity: 'medium'
  tag gid: 'V-766'
  tag rid: 'SV-44834r1_rule'
  tag stig_id: 'GEN000460'
  tag gtitle: 'GEN000460'
  tag fix_id: 'F-38271r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000044']
  tag nist: ['AC-7 a']
end
