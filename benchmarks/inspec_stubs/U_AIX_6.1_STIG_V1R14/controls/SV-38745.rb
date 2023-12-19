control 'SV-38745' do
  title 'Device files used for backup must only be readable and/or writable by root or the backup user.'
  desc 'System backups could be accidentally or maliciously overwritten and destroy the ability to recover the system if a compromise should occur.  Unauthorized users could also copy system files.'
  desc 'check', 'Check the system for world-writable device files.

Procedure:
# find / -perm -2 -a \\( -type b -o -type c \\) -exec ls -ld {} \\;

If any device file(s) used for backup are writable by users other than root, this is a finding (Typical backup devices for tape are/dev/rmt* and cd/dvd writers are /dev/cd*).'
  desc 'fix', 'Use the chmod command to remove the world-writable bit from the backup device files. 

Procedure:
# chmod o-w <back device filename>

Document all changes.'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-37183r1_chk'
  tag severity: 'medium'
  tag gid: 'V-925'
  tag rid: 'SV-38745r1_rule'
  tag stig_id: 'GEN002300'
  tag gtitle: 'GEN002300'
  tag fix_id: 'F-32459r1_fix'
  tag responsibility: ['Information Assurance Officer', 'System Administrator']
  tag ia_controls: 'ECCD-1, ECCD-2'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
