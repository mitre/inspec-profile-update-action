control 'SV-237769' do
  title 'All local interactive user home directories must have mode 0750 or less permissive.'
  desc 'Excessive permissions on local interactive user home directories may allow unauthorized access to user files by other users.'
  desc 'check', %q(Verify the assigned home directory of all local interactive users has a mode of "0750" or less permissive with the following command:

Note: This may miss interactive users that have been assigned a privileged User Identifier (UID). Evidence of interactive use may be obtained from a number of log files containing system logon information.

$ sudo ls -ld $(awk -F: '($3>=1000)&&($7 !~ /nologin/){print $6}' /etc/passwd)

drwxr-x--- 2 smithj admin 4096 Jun 5 12:41 smithj

If home directories referenced in "/etc/passwd" do not have a mode of "0750" or less permissive, this is a finding.)
  desc 'fix', 'Change the mode of interactive user’s home directories to "0750". To change the mode of a local interactive user’s home directory, use the following command:

Note: The example will be for the user "smithj".

$ sudo chmod 0750 /home/smithj'
  impact 0.5
  ref 'DPMS Target Canonical Ubuntu 18.04 LTS'
  tag check_id: 'C-32990r567709_chk'
  tag severity: 'medium'
  tag gid: 'V-237769'
  tag rid: 'SV-237769r648743_rule'
  tag stig_id: 'UBTU-18-010451'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-40942r648738_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
