control 'SV-35122' do
  title 'Files in /var/news must be owned by root or news.'
  desc 'If critical system files are not owned by a privileged user, system integrity could be compromised.'
  desc 'check', 'Check the ownership of the files in news.
# find /var/news -type f | xargs -n1 ls -lL

If any files are not owned by root or news, this is a finding.'
  desc 'fix', 'Change the ownership of the files in <path>/news to root or news.

# chown root <path>/news/*'
  impact 0.5
  ref 'DPMS Target HP-UX 11.31'
  tag check_id: 'C-34980r4_chk'
  tag severity: 'medium'
  tag gid: 'V-4277'
  tag rid: 'SV-35122r1_rule'
  tag stig_id: 'GEN006340'
  tag gtitle: 'GEN006340'
  tag fix_id: 'F-30274r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
