control 'SV-221735' do
  title 'The Oracle Linux operating system must be configured so that all local initialization files for interactive users are owned by the home directory user or root.'
  desc "Local initialization files are used to configure the user's shell environment upon logon. Malicious modification of these files could compromise accounts upon logon."
  desc 'check', %q(Verify the local initialization files of all local interactive users are owned by that user.

Check the home directory assignment for all non-privileged users on the system with the following command:

Note: The example will be for the smithj user, who has a home directory of "/home/smithj".

# awk -F: '($3>=1000)&&($7 !~ /nologin/){print $1, $3, $6}' /etc/passwd

smithj 1000 /home/smithj

Note: This may miss interactive users that have been assigned a privileged User Identifier (UID). Evidence of interactive use may be obtained from a number of log files containing system logon information.

# ls -al /home/smithj/.[^.]* | more

-rwxr-xr-x 1 smithj users 896 Mar 10 2011 .profile
-rwxr-xr-x 1 smithj users 497 Jan 6 2007 .login
-rwxr-xr-x 1 smithj users 886 Jan 6 2007 .something

If all local interactive user's initialization files are not owned by that user or root, this is a finding.)
  desc 'fix', 'Set the owner of the local initialization files for interactive users to either the directory owner or root with the following command:

Note: The example will be for the smithj user, who has a home directory of "/home/smithj".

# chown smithj /home/smithj/.[^.]*'
  impact 0.5
  ref 'DPMS Target Oracle Linux 7'
  tag check_id: 'C-36278r622261_chk'
  tag severity: 'medium'
  tag gid: 'V-221735'
  tag rid: 'SV-221735r603797_rule'
  tag stig_id: 'OL07-00-020690'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-36242r602429_fix'
  tag 'documentable'
  tag legacy: ['V-99209', 'SV-108313']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
