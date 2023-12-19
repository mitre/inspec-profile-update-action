control 'SV-45675' do
  title 'The at.allow file must be owned by root, bin, or sys.'
  desc 'If the owner of the at.allow file is not set to root, bin, or sys, unauthorized users could be allowed to view or edit sensitive information contained within the file.'
  desc 'check', '# ls -lL /etc/at.allow
If the at.allow file is not owned by root, sys, or bin, this is a finding.'
  desc 'fix', 'Change the owner of the at.allow file.
# chown root /etc/at.allow'
  impact 0.5
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-43041r1_chk'
  tag severity: 'medium'
  tag gid: 'V-4367'
  tag rid: 'SV-45675r1_rule'
  tag stig_id: 'GEN003460'
  tag gtitle: 'GEN003460'
  tag fix_id: 'F-39073r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
