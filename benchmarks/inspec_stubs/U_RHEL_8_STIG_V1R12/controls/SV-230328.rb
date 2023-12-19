control 'SV-230328' do
  title 'A separate RHEL 8 filesystem must be used for user home directories (such as /home or an equivalent).'
  desc 'The use of separate file systems for different paths can protect the system from failures resulting from a file system becoming full or failing.'
  desc 'check', %q(Verify that a separate file system has been created for non-privileged local interactive user home directories.

Check the home directory assignment for all non-privileged users, users with a User Identifier (UID) greater than 1000, on the system with the following command:

     $ sudo awk -F: '($3>=1000)&&($7 !~ /nologin/){print $1,$3,$6}' /etc/passwd

     doej 1001 /home/doej 
     publicj 1002 /home/publicj 
     smithj 1003 /home/smithj

The output of the command will give the directory/partition that contains the home directories for the non-privileged users on the system (in this example, "/home") and users’ shell. All accounts with a valid shell (such as /bin/bash) are considered interactive users.

Check that a file system/partition has been created for the nonprivileged interactive users with the following command:

Note: The partition of "/home" is used in the example.

     $ sudo grep /home /etc/fstab

     /dev/mapper/...   /home   xfs   defaults,noexec,nosuid,nodev 0 0

If a separate entry for the file system/partition containing the nonprivileged interactive user home directories does not exist, this is a finding.)
  desc 'fix', 'Migrate the "/home" directory onto a separate file system.'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 8'
  tag check_id: 'C-32997r902721_chk'
  tag severity: 'medium'
  tag gid: 'V-230328'
  tag rid: 'SV-230328r902723_rule'
  tag stig_id: 'RHEL-08-010800'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-32972r902722_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
