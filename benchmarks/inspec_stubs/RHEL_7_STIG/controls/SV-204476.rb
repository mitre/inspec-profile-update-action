control 'SV-204476' do
  title 'The Red Hat Enterprise Linux operating system must be configured so that all local initialization files have mode 0740 or less permissive.'
  desc "Local initialization files are used to configure the user's shell environment upon logon. Malicious modification of these files could compromise accounts upon logon."
  desc 'check', 'Verify that all local initialization files have a mode of "0740" or less permissive.

Check the mode on all local initialization files with the following command:

Note: The example will be for the "smithj" user, who has a home directory of "/home/smithj".

# ls -al /home/smithj/.[^.]* | more

-rwxr----- 1 smithj users 896 Mar 10 2011 .profile
-rwxr----- 1 smithj users 497 Jan 6 2007 .login
-rwxr----- 1 smithj users 886 Jan 6 2007 .something

If any local initialization files have a mode more permissive than "0740", this is a finding.'
  desc 'fix', 'Set the mode of the local initialization files to "0740" with the following command:

Note: The example will be for the "smithj" user, who has a home directory of "/home/smithj".

# chmod 0740 /home/smithj/.[^.]*'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 7'
  tag check_id: 'C-4600r88620_chk'
  tag severity: 'medium'
  tag gid: 'V-204476'
  tag rid: 'SV-204476r603261_rule'
  tag stig_id: 'RHEL-07-020710'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-4600r88621_fix'
  tag 'documentable'
  tag legacy: ['SV-86657', 'V-72033']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
