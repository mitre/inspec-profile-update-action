control 'SV-221754' do
  title 'The Oracle Linux operating system must be configured so that a separate file system is used for user home directories (such as /home or an equivalent).'
  desc 'The use of separate file systems for different paths can protect the system from failures resulting from a file system becoming full or failing.'
  desc 'check', "Verify that a separate file system/partition has been created for non-privileged local interactive user home directories.

Check the home directory assignment for all non-privileged users (those with a UID of 1000 or greater) on the system with the following command:

# awk -F: '($3>=1000)&&($7 !~ /nologin/){print $1, $3, $6, $7}' /etc/passwd

adamsj 1000 /home/adamsj /bin/bash
jacksonm 1001 /home/jacksonm /bin/bash
smithj 1002 /home/smithj /bin/bash

The output of the command will give the directory/partition that contains the home directories for the non-privileged users on the system (in this example, /home) and users' shell. All accounts with a valid shell (such as /bin/bash) are considered interactive users.

Check that a file system/partition has been created for the non-privileged interactive users with the following command:

Note: The partition of /home is used in the example.

# grep /home /etc/fstab
UUID=333ada18 /home ext4 noatime,nobarrier,nodev 1 2

If a separate entry for the file system/partition that contains the non-privileged interactive users' home directories does not exist, this is a finding."
  desc 'fix', 'Migrate the "/home" directory onto a separate file system/partition.'
  impact 0.3
  ref 'DPMS Target Oracle Linux 7'
  tag check_id: 'C-23469r622267_chk'
  tag severity: 'low'
  tag gid: 'V-221754'
  tag rid: 'SV-221754r603803_rule'
  tag stig_id: 'OL07-00-021310'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-23458r419335_fix'
  tag 'documentable'
  tag legacy: ['SV-108351', 'V-99247']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
