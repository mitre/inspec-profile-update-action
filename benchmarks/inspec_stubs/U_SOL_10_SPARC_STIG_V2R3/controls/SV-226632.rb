control 'SV-226632' do
  title 'The cron.allow file must be owned by root, bin, or sys.'
  desc 'If the owner of the cron.allow file is not set to root, bin, or sys, the possibility exists for an unauthorized user to view or to edit sensitive information.'
  desc 'check', '# ls -lL /etc/cron.d/cron.allow
If the cron.allow file is not owned by root, sys, or bin, this is a finding.'
  desc 'fix', '# chown root /etc/cron.d/cron.allow'
  impact 0.5
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-28793r483308_chk'
  tag severity: 'medium'
  tag gid: 'V-226632'
  tag rid: 'SV-226632r603265_rule'
  tag stig_id: 'GEN003240'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-28781r483309_fix'
  tag 'documentable'
  tag legacy: ['SV-27366', 'V-4361']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
