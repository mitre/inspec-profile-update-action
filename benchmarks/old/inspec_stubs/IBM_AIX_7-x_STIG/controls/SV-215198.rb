control 'SV-215198' do
  title 'The AIX root accounts home directory (other than /) must have mode 0700.'
  desc "Users' home directories/folders may contain information of a sensitive nature. Non-privileged users should coordinate any sharing of information with an SA through shared resources."
  desc 'check', %q(Check the mode of the root home directory by running the following commands:
# ls -ld `grep "^root" /etc/passwd | awk -F":" '{print $6}'`

The above command should yield the following output:
drwx------   22 root     system     4096 Sep 06 18:00 /root

If the mode of the directory is not equal to "0700", this is a finding.)
  desc 'fix', 'Use the following command to change protections for the root home directory: 
# chmod 0700 /root.'
  impact 0.5
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16396r294045_chk'
  tag severity: 'medium'
  tag gid: 'V-215198'
  tag rid: 'SV-215198r508663_rule'
  tag stig_id: 'AIX7-00-001039'
  tag gtitle: 'SRG-OS-000480-GPOS-00230'
  tag fix_id: 'F-16394r294046_fix'
  tag 'documentable'
  tag legacy: ['V-91753', 'SV-101851']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
