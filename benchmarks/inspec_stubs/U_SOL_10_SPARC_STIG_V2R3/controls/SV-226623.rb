control 'SV-226623' do
  title 'Cron and crontab directories must not have extended ACLs.'
  desc 'To protect the integrity of scheduled system jobs and to prevent malicious modification to these jobs, crontab files must be secured.  ACLs on cron and crontab directories may provide unauthorized access to these directories.  Unauthorized modifications to these directories or their contents may result in the addition of unauthorized cron jobs or deny service to authorized cron jobs.'
  desc 'check', 'Check the permissions of the crontab directories.
# ls -ld /var/spool/cron/crontabs/

If the permissions include a "+", the directory has an extended ACL and this is a finding.'
  desc 'fix', 'Remove the extended ACL from the directory.
# chmod A- /var/spool/cron/crontabs/'
  impact 0.5
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-28784r483281_chk'
  tag severity: 'medium'
  tag gid: 'V-226623'
  tag rid: 'SV-226623r603265_rule'
  tag stig_id: 'GEN003110'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-28772r483282_fix'
  tag 'documentable'
  tag legacy: ['V-22387', 'SV-26538']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
