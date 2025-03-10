control 'SV-221737' do
  title 'The Oracle Linux operating system must be configured so that all local initialization files have mode 0740 or less permissive.'
  desc "Local initialization files are used to configure the user's shell environment upon logon. Malicious modification of these files could compromise accounts upon logon."
  desc 'check', 'Verify that all local initialization files have a mode of "0740" or less permissive.

Check the mode on all local initialization files with the following command:

Note: The example will be for the "smithj" user, who has a home directory of "/home/smithj".

     # ls -al /home/smithj/.[^.]* | more

     -rw-------. 1 smithj users 2984 Apr 27 19:02 .bash_history
     -rw-r--r--. 1 smithj users   18 Aug 21  2019 .bash_logout
     -rw-r--r--. 1 smithj users  193 Aug 21  2019 .bash_profile

If any local initialization files have a mode more permissive than "0740", this is a finding.'
  desc 'fix', 'Set the mode of the local initialization files to "0740" with the following command:

Note: The example will be for the "smithj" user, who has a home directory of "/home/smithj".

     # chmod 0740 /home/smithj/.[^.]*'
  impact 0.5
  ref 'DPMS Target Oracle Linux 7'
  tag check_id: 'C-36280r917849_chk'
  tag severity: 'medium'
  tag gid: 'V-221737'
  tag rid: 'SV-221737r917851_rule'
  tag stig_id: 'OL07-00-020710'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-36244r917850_fix'
  tag 'documentable'
  tag legacy: ['V-99213', 'SV-108317']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
