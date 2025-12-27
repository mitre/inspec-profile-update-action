control 'SV-226873' do
  title 'The at.deny file must be owned by root, bin, or sys.'
  desc 'If the owner of the at.deny file is not set to root, bin, or sys, unauthorized users could be allowed to view or edit sensitive information contained within the file.'
  desc 'check', '# ls -lL /etc/cron.d/at.deny
If the at.deny file is not owned by root, sys, or bin,  this is a finding.'
  desc 'fix', 'Change the owner of the at.deny file.
# chown root /etc/cron.d/at.deny'
  impact 0.5
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-29035r484903_chk'
  tag severity: 'medium'
  tag gid: 'V-226873'
  tag rid: 'SV-226873r603265_rule'
  tag stig_id: 'GEN003480'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-29023r484904_fix'
  tag 'documentable'
  tag legacy: ['SV-27396', 'V-4368']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
