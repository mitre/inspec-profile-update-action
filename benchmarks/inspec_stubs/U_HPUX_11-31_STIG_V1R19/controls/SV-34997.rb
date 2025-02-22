control 'SV-34997' do
  title 'The at.allow file must be owned by root, bin, or sys.'
  desc 'If the owner of the at.allow file is not set to root, sys, or bin, unauthorized users could be allowed to view or edit sensitive information contained within the file.'
  desc 'check', '# ls -lL /var/adm/cron/at.allow

If the at.allow file is not owned by root, sys or bin, this is a finding.'
  desc 'fix', 'Change the owner of the at.allow file.
   # chown root /var/adm/cron/at.allow'
  impact 0.5
  ref 'DPMS Target HP-UX 11.31'
  tag check_id: 'C-34872r1_chk'
  tag severity: 'medium'
  tag gid: 'V-4367'
  tag rid: 'SV-34997r1_rule'
  tag stig_id: 'GEN003460'
  tag gtitle: 'GEN003460'
  tag fix_id: 'F-30202r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
