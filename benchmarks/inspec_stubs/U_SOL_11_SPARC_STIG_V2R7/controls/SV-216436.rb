control 'SV-216436' do
  title 'The operating system must have no unowned files.'
  desc "A new user who is assigned a deleted user's user ID or group ID may then end up owning these files, and thus have more access on the system than was intended."
  desc 'check', 'The root role is required.

Identify all files that are owned by a user or group not listed in /etc/passwd or /etc/group

# find / \\( -fstype nfs -o -fstype cachefs -o -fstype autofs \\
-o -fstype ctfs -o -fstype mntfs -o -fstype objfs \\
-o -fstype proc \\) -prune \\( -nouser -o -nogroup \\) -ls

If output is produced, this is a finding.'
  desc 'fix', 'The root role is required.

Correct or justify any items discovered in the Check step. Determine the existence of any files that are not attributed to current users or groups on the system, and determine the best course of action in accordance with site policy. Remove the files and directories or change their ownership.'
  impact 0.5
  ref 'DPMS Target Solaris 11 SPARC'
  tag check_id: 'C-17672r371396_chk'
  tag severity: 'medium'
  tag gid: 'V-216436'
  tag rid: 'SV-216436r603267_rule'
  tag stig_id: 'SOL-11.1-070200'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-17670r371397_fix'
  tag 'documentable'
  tag legacy: ['V-48039', 'SV-60911']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
