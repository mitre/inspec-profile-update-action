control 'SV-216204' do
  title 'The operator must document all file system objects that have non-standard access control list settings.'
  desc 'Access Control Lists allow an object owner to expand permissions on an object to specific users and groups in addition to the standard permission model. Non-standard Access Control List settings can allow unauthorized users to modify critical files.'
  desc 'check', 'The root role is required.

Identify all file system objects that have non-standard access control lists enabled.

# find / \\( -fstype nfs -o -fstype cachefs -o -fstype autofs \\
-o -fstype ctfs -o -fstype mntfs -o -fstype objfs \\
-o -fstype proc \\) -prune -o -acl -ls

This command should return no output. If output is created, this is a finding.

If the files are approved to have ACLs by organizational security policy, document the files and the reason that ACLs are required.'
  desc 'fix', 'The root role is required.

Remove ACLs that are not approved in the security policy.

For ZFS file systems, remove all extended ACLs with the following command:

# chmod A- [filename]

For UFS file systems

Determine the ACLs that are set on a file:

# getfacl [filename]

Remove any ACL configurations that are set:

# setfacl -d [ACL] [filename]'
  impact 0.5
  ref 'DPMS Target Solaris 11 X86'
  tag check_id: 'C-17442r372994_chk'
  tag severity: 'medium'
  tag gid: 'V-216204'
  tag rid: 'SV-216204r603268_rule'
  tag stig_id: 'SOL-11.1-070260'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-17440r372995_fix'
  tag 'documentable'
  tag legacy: ['V-48029', 'SV-60901']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
