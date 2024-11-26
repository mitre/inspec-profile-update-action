control 'SV-226858' do
  title 'The cron.deny file must be owned by root, bin, or sys.'
  desc 'Cron daemon control files restrict the scheduling of automated tasks and must be protected.'
  desc 'check', 'Check the ownership of the cron.deny file.

# ls -lL /etc/cron.d/cron.deny
If the cron.deny file is not owned by root, sys, or bin, this is a finding.'
  desc 'fix', 'Change the ownership of the cron.deny file to root, sys, or bin.

# chown root /etc/cron.d/cron.deny'
  impact 0.5
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-29020r484858_chk'
  tag severity: 'medium'
  tag gid: 'V-226858'
  tag rid: 'SV-226858r603265_rule'
  tag stig_id: 'GEN003260'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-29008r484859_fix'
  tag 'documentable'
  tag legacy: ['SV-27371', 'V-4430']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
