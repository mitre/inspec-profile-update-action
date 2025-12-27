control 'SV-38250' do
  title 'Crontabs must be owned by root or the crontab creator.'
  desc 'To protect the integrity of scheduled system jobs and prevent malicious modification to these jobs, crontab files must be secured.'
  desc 'check', 'List all crontabs on the system. 
# ls -lL /var/spool/cron/crontabs/*

If any crontab file is not owned by root or the creating user, this is a finding.'
  desc 'fix', 'Change the crontab file owner to root or the crontab creator.
# chown root <crontab file>'
  impact 0.5
  ref 'DPMS Target HP-UX 11.23'
  tag check_id: 'C-36480r1_chk'
  tag severity: 'medium'
  tag gid: 'V-11994'
  tag rid: 'SV-38250r1_rule'
  tag stig_id: 'GEN003040'
  tag gtitle: 'GEN003040'
  tag fix_id: 'F-31827r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'DCSL-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
