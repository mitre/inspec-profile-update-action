control 'SV-216434' do
  title 'World-writable files must not exist.'
  desc "Data in world-writable files can be read, modified, and potentially compromised by any user on the system. World-writable files may also indicate an incorrectly written script or program that could potentially be the cause of a larger compromise to the system's integrity."
  desc 'check', 'The root role is required.

Check for the existence of world-writable files.

# find / \\( -fstype nfs -o -fstype cachefs -o -fstype autofs \\
-o -fstype ctfs -o -fstype mntfs -o -fstype objfs \\
-o -fstype proc \\) -prune -o -type f -perm -0002 -print
If output is produced, this is a finding.'
  desc 'fix', 'The root role is required.

Change the permissions of the files identified in the check step to remove the world-writable permission.

# pfexec chmod o-w [filename]'
  impact 0.5
  ref 'DPMS Target Solaris 11 SPARC'
  tag check_id: 'C-17670r371390_chk'
  tag severity: 'medium'
  tag gid: 'V-216434'
  tag rid: 'SV-216434r603267_rule'
  tag stig_id: 'SOL-11.1-070180'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-17668r371391_fix'
  tag 'documentable'
  tag legacy: ['SV-60935', 'V-48063']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
