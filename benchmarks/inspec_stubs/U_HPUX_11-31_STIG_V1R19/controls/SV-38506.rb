control 'SV-38506' do
  title 'Device files used for backup must only be readable and/or writable by root or the backup user.'
  desc 'System backups could be accidentally or maliciously overwritten and destroy the ability to recover the system if a compromise should occur.  Unauthorized users could also copy system files.'
  desc 'check', 'Check the system for device files read/write enabled for users other than root or the backup user.

Example:
# find / \\( -perm -0020 -o -perm -0040 -o -perm -0002 -o -perm -0004 \\) -a \\( -type b -o -type c -o -type n \\) -exec ls -ld {} \\;
If any device files used for backup are read/write enabled for users other than root, this is a finding.'
  desc 'fix', 'Use the chmod command to remove the read/write bit(s) from the backup device files. 

# chmod o-r <b/u device file name>
# chmod o-w <b/u device file name>
# chmod g-r <b/u device file name>
# chmod g-w <b/u device file name>


Document all changes.'
  impact 0.5
  ref 'DPMS Target HP-UX 11.31'
  tag check_id: 'C-36416r1_chk'
  tag severity: 'medium'
  tag gid: 'V-925'
  tag rid: 'SV-38506r1_rule'
  tag stig_id: 'GEN002300'
  tag gtitle: 'GEN002300'
  tag fix_id: 'F-31754r1_fix'
  tag responsibility: ['Information Assurance Officer', 'System Administrator']
  tag ia_controls: 'ECCD-1, ECCD-2'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
