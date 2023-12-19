control 'SV-216200' do
  title 'The operating system must have no files with extended attributes.'
  desc 'Attackers or malicious users could hide information, exploits, etc. in extended attribute areas. Since extended attributes are rarely used, it is important to find files with extended attributes set and correct these attributes.'
  desc 'check', 'The root role is required.

Identify all files with extended attributes.

# find / \\( -fstype nfs -o -fstype cachefs -o -fstype autofs \\
-o -fstype ctfs -o -fstype mntfs -o -fstype objfs \\
-o -fstype proc \\) -prune -o -xattr -ls

If output is produced, this is a finding.'
  desc 'fix', 'The root role is required.

Correct or justify any items discovered in the Check step. Determine the existence of any files having extended file attributes, and determine the best course of action in accordance with site policy.

Remove the files or the extended attributes.'
  impact 0.3
  ref 'DPMS Target Solaris 11 X86'
  tag check_id: 'C-17438r372982_chk'
  tag severity: 'low'
  tag gid: 'V-216200'
  tag rid: 'SV-216200r603268_rule'
  tag stig_id: 'SOL-11.1-070210'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-17436r372983_fix'
  tag 'documentable'
  tag legacy: ['V-48037', 'SV-60909']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
