control 'SV-226618' do
  title "Crontab files must be group-owned by root, sys, or the crontab creator's primary group."
  desc 'To protect the integrity of scheduled system jobs and prevent malicious modification to these jobs, crontab files must be secured.'
  desc 'check', "Check the group ownership of the crontab files.
# ls -lL /var/spool/cron/crontabs/
If the group owner is not root, sys, or the crontab owner's primary group, this is a finding."
  desc 'fix', "Change the group owner of the crontab file to root, sys, or the crontab's primary group.
Procedure:
# chgrp root [crontab file]"
  impact 0.5
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-28779r483266_chk'
  tag severity: 'medium'
  tag gid: 'V-226618'
  tag rid: 'SV-226618r603265_rule'
  tag stig_id: 'GEN003050'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-28767r483267_fix'
  tag 'documentable'
  tag legacy: ['SV-41044', 'V-22385']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
