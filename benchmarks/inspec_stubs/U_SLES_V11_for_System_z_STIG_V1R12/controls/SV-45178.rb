control 'SV-45178' do
  title 'Device files used for backup must only be readable and/or writable by root or the backup user.'
  desc 'System backups could be accidentally or maliciously overwritten and destroy the ability to recover the system if a compromise should occur.  Unauthorized users could also copy system files.'
  desc 'check', 'Check the system for world-writable device files.

Procedure:
# find / -perm -2 -a \\( -type b -o -type c \\) -exec ls -ld {} \\;

If any device file(s) used for backup are writable by users other than root, this is a finding.'
  desc 'fix', 'Use the chmod command to remove the world-writable bit from the backup device files. 

Procedure:
# chmod o-w <back device filename>

Document all changes.'
  impact 0.5
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-42523r1_chk'
  tag severity: 'medium'
  tag gid: 'V-925'
  tag rid: 'SV-45178r1_rule'
  tag stig_id: 'GEN002300'
  tag gtitle: 'GEN002300'
  tag fix_id: 'F-38576r1_fix'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
