control 'SV-234994' do
  title "All SUSE operating system local interactive user home directories must be group-owned by the home directory owner's primary group."
  desc 'If the Group Identifier (GID) of a local interactive user’s home directory is not the same as the primary GID of the user, this would allow unauthorized access to the user’s files, and users that share the same group may not be able to access files that they legitimately should.'
  desc 'check', %q(Verify the assigned home directory of all SUSE operating system local interactive users is group-owned by that user's primary GID.

Check the home directory assignment for all non-privileged users on the system with the following command:

Note: This may miss local interactive users that have been assigned a privileged User Identifier (UID). Evidence of interactive use may be obtained from a number of log files containing system logon information. The returned directory "/home/smithj" is used as an example.

> awk -F: '($3>=1000)&&($7 !~ /nologin/){print $4, $6}' /etc/passwd)
250:/home/smithj

Check the user's primary group with the following command:

> grep users /etc/group
users:x:250:smithj,jonesj,jacksons

If the user home directory referenced in "/etc/passwd" is not group-owned by that user's primary GID, this is a finding.)
  desc 'fix', %q(Change the group owner of a SUSE operating system local interactive user's home directory to the group found in "/etc/passwd". To change the group owner of a local interactive user's home directory, use the following command:

Note: The example will be for the user "smithj", who has a home directory of "/home/smithj", and has a primary group of users.

> sudo chgrp users /home/smithj)
  impact 0.5
  ref 'DPMS Target SUSE Linux Enterprise Server 15'
  tag check_id: 'C-38182r619251_chk'
  tag severity: 'medium'
  tag gid: 'V-234994'
  tag rid: 'SV-234994r622137_rule'
  tag stig_id: 'SLES-15-040100'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-38145r619252_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
