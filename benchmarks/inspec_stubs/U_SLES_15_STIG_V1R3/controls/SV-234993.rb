control 'SV-234993' do
  title 'All SUSE operating system local interactive user home directories must have mode 0750 or less permissive.'
  desc 'Excessive permissions on local interactive user home directories may allow unauthorized access to user files by other users.'
  desc 'check', %q(Verify the assigned home directory of all SUSE operating system local interactive users has a mode of "0750" or less permissive.

Check the home directory assignment for all non-privileged users on the system with the following command:

Note: This may miss interactive users that have been assigned a privileged User Identifier (UID). Evidence of interactive use may be obtained from a number of log files containing system logon information.

> ls -ld $(awk -F: '($3>=1000)&&($7 !~ /nologin/){print $6}' /etc/passwd)
-rwxr-x--- 1 smithj users 18 Mar 5 17:06 /home/smithj

If home directories referenced in "/etc/passwd" do not have a mode of "0750" or less permissive, this is a finding.)
  desc 'fix', %q(Change the mode of SUSE operating system local interactive user's home directories to "0750". To change the mode of a local interactive user's home directory, use the following command:

Note: The example will be for the user "smithj".

> sudo chmod 0750 /home/smithj)
  impact 0.5
  ref 'DPMS Target SUSE Linux Enterprise Server 15'
  tag check_id: 'C-38181r619248_chk'
  tag severity: 'medium'
  tag gid: 'V-234993'
  tag rid: 'SV-234993r622137_rule'
  tag stig_id: 'SLES-15-040090'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-38144r619249_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
