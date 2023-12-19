control 'SV-217184' do
  title 'A separate file system must be used for SUSE operating system user home directories (such as /home or an equivalent).'
  desc 'The use of separate file systems for different paths can protect the system from failures resulting from a file system becoming full or failing.'
  desc 'check', "Verify that a separate file system/partition has been created for SUSE operating system non-privileged local interactive user home directories.

Check the home directory assignment for all non-privileged users (those with a UID greater than 1000) on the system with the following command:

# awk -F: '($3>=1000)&&($7 !~ /nologin/){print $1, $3, $6, $7}' /etc/passwd

adamsj 1002  /home/adamsj /bin/bash
jacksonm 1003 /home/jacksonm /bin/bash
smithj  1001 /home/smithj /bin/bash

The output of the command will give the directory/partition that contains the home directories for the non-privileged users on the system (in this example, /home) and user's shell. All accounts with a valid shell (such as /bin/bash) are considered interactive users.

Check that a file system/partition has been created for the non-privileged interactive users with the following command:

Note: The partition of /home is used in the example.

# grep /home /etc/fstab
UUID=333ada18    /home   ext4   noatime,nobarrier,nodev   1 2

If a separate entry for the file system/partition that contains the non-privileged interactive users' home directories does not exist, this is a finding."
  desc 'fix', 'Create a separate file system/partition for SUSE operating system non-privileged local interactive user home directories.

Migrate the non-privileged local interactive user home directories onto the separate file system/partition.'
  impact 0.3
  ref 'DPMS Target SUSE Linux Enterprise Server 12'
  tag check_id: 'C-18412r622356_chk'
  tag severity: 'low'
  tag gid: 'V-217184'
  tag rid: 'SV-217184r603893_rule'
  tag stig_id: 'SLES-12-010850'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-18410r369709_fix'
  tag 'documentable'
  tag legacy: ['SV-91957', 'V-77261']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
