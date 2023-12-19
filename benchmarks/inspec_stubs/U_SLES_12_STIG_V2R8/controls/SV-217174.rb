control 'SV-217174' do
  title 'All SUSE operating system local interactive user home directories must be group-owned by the home directory owners primary group.'
  desc 'If the Group Identifier (GID) of a local interactive user’s home directory is not the same as the primary GID of the user, this would allow unauthorized access to the user’s files, and users that share the same group may not be able to access files that they legitimately should.'
  desc 'check', %q(Verify the assigned home directory of all SUSE operating system local interactive users is group-owned by that user's primary GID.

Check the home directory assignment for all non-privileged users on the system with the following command:

Note: This may miss local interactive users that have been assigned a privileged UID. Evidence of interactive use may be obtained from a number of log files containing system logon information. The returned directory "/home/smithj" is used as an example.

# awk -F: '($3>=1000)&&($7 !~ /nologin/){print $4, $6}' /etc/passwd
250 /home/smithj

Check the user's primary group with the following command:

# grep users /etc/group
users:x:250:smithj,jonesj,jacksons

If the user home directory referenced in "/etc/passwd" is not group-owned by that user's primary GID, this is a finding.)
  desc 'fix', %q(Change the group owner of a SUSE operating system local interactive user's home directory to the group found in "/etc/passwd". To change the group owner of a local interactive user's home directory, use the following command:

Note: The example will be for the user "smithj", who has a home directory of "/home/smithj", and has a primary group of users.

# chgrp users /home/smithj)
  impact 0.5
  ref 'DPMS Target SUSE Linux Enterprise Server 12'
  tag check_id: 'C-18402r622352_chk'
  tag severity: 'medium'
  tag gid: 'V-217174'
  tag rid: 'SV-217174r603889_rule'
  tag stig_id: 'SLES-12-010750'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-18400r369679_fix'
  tag 'documentable'
  tag legacy: ['SV-91907', 'V-77211']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
