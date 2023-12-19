control 'SV-216417' do
  title 'The sticky bit must be set on all world writable directories.'
  desc %q(Files in directories that have had the "sticky bit" enabled can only be deleted by users that have both write permissions for the directory in which the file resides, as well as ownership of the file or directory, or have sufficient privileges. As this prevents users from overwriting each others' files, whether it be accidental or malicious, it is generally appropriate for most world-writable directories (e.g., /tmp).)
  desc 'check', 'The root role is required.

Identify all world-writable directories without the "sticky bit" set.

# find / \\( -fstype nfs -o -fstype cachefs -o -fstype autofs \\
   -o -fstype ctfs -o -fstype mntfs -o -fstype objfs \\
   -o -fstype proc \\) -prune -o -type d \\( -perm -0002 \\
   -a ! -perm -1000 \\) -ls

Output of this command identifies world-writable directories without the "sticky bit" set.  If output is created, this is a finding.'
  desc 'fix', 'The root role is required.

Ensure that the "sticky bit" is set on any directories identified during the check steps.

# chmod +t [directory name]'
  impact 0.5
  ref 'DPMS Target Solaris 11 SPARC'
  tag check_id: 'C-17653r371339_chk'
  tag severity: 'medium'
  tag gid: 'V-216417'
  tag rid: 'SV-216417r603267_rule'
  tag stig_id: 'SOL-11.1-070010'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-17651r371340_fix'
  tag 'documentable'
  tag legacy: ['V-48137', 'SV-61009']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
