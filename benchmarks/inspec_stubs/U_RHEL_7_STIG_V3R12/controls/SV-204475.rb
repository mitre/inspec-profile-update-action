control 'SV-204475' do
  title 'The Red Hat Enterprise Linux operating system must be configured so that all local initialization files for local interactive users are be group-owned by the users primary group or root.'
  desc "Local initialization files for interactive users are used to configure the user's shell environment upon logon. Malicious modification of these files could compromise accounts upon logon."
  desc 'check', %q(Verify the local initialization files of all local interactive users are group-owned by that user's primary Group Identifier (GID).

Check the home directory assignment for all nonprivileged users on the system with the following command:

Note: The example will be for the smithj user, who has a home directory of "/home/smithj" and a primary group of "users".

     # awk -F: '($4>=1000)&&($7 !~ /nologin/){print $1, $4, $6}' /etc/passwd
     
     smithj 1000 /home/smithj

     # grep 1000 /etc/group
     
     users:x:1000:smithj,jonesj,jacksons 

Note: This may miss interactive users that have been assigned a privileged User Identifier (UID). Evidence of interactive use may be obtained from a number of log files containing system logon information.

Check the group owner of all local interactive users' initialization files with the following command:

     # ls -al /home/smithj/.[^.]* | more

     -rw-------. 1 smithj users 2984 Apr 27 19:02 .bash_history
     -rw-r--r--. 1 smithj users   18 Aug 21  2019 .bash_logout
     -rw-r--r--. 1 smithj users  193 Aug 21  2019 .bash_profile

If all local interactive users' initialization files are not group-owned by that user's primary GID, this is a finding.)
  desc 'fix', %q(Change the group owner of a local interactive user's files to the group found in "/etc/passwd" for the user. To change the group owner of a local interactive user's home directory, use the following command:

Note: The example will be for the user smithj, who has a home directory of "/home/smithj" and has a primary group of users.

     # chgrp users /home/smithj/.[^.]*)
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 7'
  tag check_id: 'C-4599r917822_chk'
  tag severity: 'medium'
  tag gid: 'V-204475'
  tag rid: 'SV-204475r917824_rule'
  tag stig_id: 'RHEL-07-020700'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-4599r917823_fix'
  tag 'documentable'
  tag legacy: ['V-72031', 'SV-86655']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
