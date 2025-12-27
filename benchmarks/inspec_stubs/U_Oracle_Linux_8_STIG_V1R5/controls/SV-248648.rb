control 'SV-248648' do
  title 'A separate OL 8 filesystem must be used for user home directories (such as "/home" or an equivalent).'
  desc 'The use of separate file systems for different paths can protect the system from failures resulting from a file system becoming full or failing.'
  desc 'check', %q(Verify that a separate file system/partition has been created for non-privileged local interactive user home directories. 
 
Check the home directory assignment for all non-privileged users, users with a User Identifier (UID) greater than 1000, on the system with the following command: 
 
$ sudo awk -F: '($3>=1000)&&($1!="nobody"){print $1,$3,$6}' /etc/passwd 
 
adamsj 1001 /home/adamsj 
jacksonm 1002 /home/jacksonm 
smithj 1003 /home/smithj 
 
The output of the command will give the directory/partition that contains the home directories for the non-privileged users on the system (in this example, "/home") and users’ shell. All accounts with a valid shell (such as "/bin/bash") are considered interactive users. 
 
Check that a file system/partition has been created for the non-privileged interactive users with the following command. 
 
Note: The partition of "/home" is used in the example. 
 
$ sudo grep /home /etc/fstab 
 
UUID=333ada18 /home ext4 noatime,nobarrier,nodev 1 2 
 
If a separate entry for the file system/partition that contains the non-privileged interactive users' home directories does not exist, this is a finding.)
  desc 'fix', 'Migrate the "/home" directory onto a separate file system/partition.'
  impact 0.5
  ref 'DPMS Target Oracle Linux 8'
  tag check_id: 'C-52082r779508_chk'
  tag severity: 'medium'
  tag gid: 'V-248648'
  tag rid: 'SV-248648r779510_rule'
  tag stig_id: 'OL08-00-010800'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-52036r779509_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
