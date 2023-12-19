control 'SV-252971' do
  title "All TOSS local interactive user home directories must be owned by the user's primary group."
  desc "Users' home directories/folders may contain information of a sensitive nature. Non-privileged users should coordinate any sharing of information with an SA through shared resources."
  desc 'check', %q(Check that all user home directories are owned by the user's primary group with the following command:

$ awk -F: '($3>=1000)&&($7 !~ /nologin/)&&("stat -c '%g' " $6 | getline dir_group)&&(dir_group!=$4){print $1,$6}' /etc/passwd
admin /home/admin

Check each user's primary group with the following command (example command is for the "admin" user):

$ sudo grep "^admin" /etc/group
admin:x:250:smithj,jonesj,jacksons

If the user home directory referenced in "/etc/passwd" is not group-owned by that user's primary GID, this is a finding.)
  desc 'fix', %q(Change the group owner of interactive user's home directories to that users primary group. To change the group owner of a local interactive user's home directory, use the following command:

Note: The example will be for the user "smithj."

$ sudo chgrp smithj /home/smithj)
  impact 0.5
  ref 'DPMS Target TOSS 4'
  tag check_id: 'C-56424r824235_chk'
  tag severity: 'medium'
  tag gid: 'V-252971'
  tag rid: 'SV-252971r824237_rule'
  tag stig_id: 'TOSS-04-020320'
  tag gtitle: 'SRG-OS-000480-GPOS-00230'
  tag fix_id: 'F-56374r824236_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
