control 'SV-226630' do
  title 'The cron.deny file must not have an extended ACL.'
  desc 'If file permissions for cron.deny are more permissive than 0700, sensitive information could be viewed or edited by unauthorized users.'
  desc 'check', 'Check the permissions of the file.
# ls -lL /etc/cron.d/cron.deny
If the permissions include a "+", the file has an extended ACL and this is a finding.'
  desc 'fix', 'Remove the extended ACL from the file.
# chmod A- /etc/cron.d/cron.deny'
  impact 0.5
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-28791r483302_chk'
  tag severity: 'medium'
  tag gid: 'V-226630'
  tag rid: 'SV-226630r603265_rule'
  tag stig_id: 'GEN003210'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-28779r483303_fix'
  tag 'documentable'
  tag legacy: ['SV-26546', 'V-22389']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
