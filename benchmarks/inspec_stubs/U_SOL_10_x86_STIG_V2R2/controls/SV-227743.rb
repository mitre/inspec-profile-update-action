control 'SV-227743' do
  title 'Crontabs must be owned by root or the crontab creator.'
  desc 'To protect the integrity of scheduled system jobs and prevent malicious modification to these jobs, crontab files must be secured.'
  desc 'check', 'List all crontabs on the system.  
# ls -lL /var/spool/cron/crontabs/

If any crontab is not owned by root or the creating user, this is a finding.'
  desc 'fix', 'Change the crontab owner to root or the crontab creator.
# chown root <crontab file>'
  impact 0.5
  ref 'DPMS Target Solaris 10 X86'
  tag check_id: 'C-29905r488813_chk'
  tag severity: 'medium'
  tag gid: 'V-227743'
  tag rid: 'SV-227743r603266_rule'
  tag stig_id: 'GEN003040'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-29893r488814_fix'
  tag 'documentable'
  tag legacy: ['V-11994', 'SV-27333']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
