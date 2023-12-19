control 'SV-45898' do
  title 'The /etc/news/passwd.nntp file (or equivalent) must have mode 0600 or less permissive.'
  desc 'File permissions more permissive than 0600 for "/etc/news/passwd.nntp" may allow access to privileged information by system intruders or malicious users.'
  desc 'check', 'Check "/etc/news/passwd.nntp" permissions:

# ls -lL /etc/news/passwd.nntp

If "/etc/news/passwd.nntp" has a mode more permissive than 0600, this is a finding.'
  desc 'fix', 'Change the mode of the "/etc/news/passwd.nntp" file.
# chmod 0600 /etc/news/passwd.nntp'
  impact 0.5
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-43209r1_chk'
  tag severity: 'medium'
  tag gid: 'V-4276'
  tag rid: 'SV-45898r1_rule'
  tag stig_id: 'GEN006320'
  tag gtitle: 'GEN006320'
  tag fix_id: 'F-39276r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
