control 'SV-226871' do
  title 'The at.allow file must be owned by root, bin, or sys.'
  desc 'If the owner of the at.allow file is not set to root, bin, or sys, unauthorized users could be allowed to view or edit sensitive information contained within the file.'
  desc 'check', '# ls -lL /etc/cron.d/at.allow
If the at.allow file is not owned by root, sys, or bin,  this is a finding.'
  desc 'fix', 'Change the owner of the at.allow file.
# chown root /etc/cron.d/at.allow'
  impact 0.5
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-29033r484897_chk'
  tag severity: 'medium'
  tag gid: 'V-226871'
  tag rid: 'SV-226871r603265_rule'
  tag stig_id: 'GEN003460'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-29021r484898_fix'
  tag 'documentable'
  tag legacy: ['V-4367', 'SV-27392']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
