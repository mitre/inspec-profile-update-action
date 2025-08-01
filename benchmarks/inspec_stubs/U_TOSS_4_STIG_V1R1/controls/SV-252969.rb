control 'SV-252969' do
  title 'All TOSS local interactive user home directories must have mode 0770 or less permissive.'
  desc "Users' home directories/folders may contain information of a sensitive nature. Non-privileged users should coordinate any sharing of information with an SA through shared resources."
  desc 'check', "Verify the operating system limits the ability of non-privileged users to grant other users direct access to the contents of their home directories/folders.

Ensure that the user permissions on all user home directories is set to 770 permissions with the following command:

$ find $(awk -F: '($3>=1000)&&($7 !~ /nologin/){print $6}' /etc/passwd) -maxdepth 0 -not -perm 770 -ls

If there is any output, this is a finding."
  desc 'fix', %q(Change the mode of interactive user's home directories to "0770." To change the mode of a local interactive user's home directory, use the following command:

Note: The example will be for the user "smithj."

$ sudo chmod 0770 /home/smithj)
  impact 0.5
  ref 'DPMS Target TOSS 4'
  tag check_id: 'C-56422r824229_chk'
  tag severity: 'medium'
  tag gid: 'V-252969'
  tag rid: 'SV-252969r824231_rule'
  tag stig_id: 'TOSS-04-020300'
  tag gtitle: 'SRG-OS-000480-GPOS-00230'
  tag fix_id: 'F-56372r824230_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
