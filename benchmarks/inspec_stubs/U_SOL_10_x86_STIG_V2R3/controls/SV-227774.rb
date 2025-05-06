control 'SV-227774' do
  title 'The "at" directory must be group-owned by root, bin, or sys.'
  desc %q(If the "at" directory's group owner is not root, bin, or sys, unauthorized users could be allowed to view or edit files containing sensitive information within the directory.)
  desc 'check', 'Check the group ownership of the "at" directory.

Procedure:
# ls -lLd /var/spool/cron/atjobs

If the "at" directory is not group-owned by root, bin, or sys, this is a finding.'
  desc 'fix', 'Change the group ownership of the "at" directory to root, bin, or sys.

Procedure:
# chgrp sys /var/spool/cron/atjobs'
  impact 0.5
  ref 'DPMS Target Solaris 10 X86'
  tag check_id: 'C-29936r489676_chk'
  tag severity: 'medium'
  tag gid: 'V-227774'
  tag rid: 'SV-227774r603266_rule'
  tag stig_id: 'GEN003430'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-29924r489677_fix'
  tag 'documentable'
  tag legacy: ['V-22396', 'SV-40414']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
