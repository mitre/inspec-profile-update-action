control 'SV-221728' do
  title 'The Oracle Linux operating system must be configured so that all local interactive users have a home directory assigned and defined in the /etc/passwd file.'
  desc 'If local interactive users are not assigned a valid home directory, there is no place for the storage and control of files they should own.
In addition, if a local interactive user has a home directory defined that does not exist, the user may be given access to the / directory as the current working directory upon logon. This could create a Denial of Service because the user would not be able to access their logon configuration files, and it may give them visibility to system files they normally would not be able to access.'
  desc 'check', %q(Verify local interactive users on the system have a home directory assigned and the directory exists.

Check the home directory assignment for all local interactive non-privileged users on the system with the following command:

# awk -F: '($3>=1000)&&($7 !~ /nologin/){print $1, $3, $6}' /etc/passwd

smithj 1001 /home/smithj

Note: This may miss interactive users that have been assigned a privileged UID. Evidence of interactive use may be obtained from a number of log files containing system logon information.

Check that all referenced home directories exist with the following command:

# pwck -r
user 'smithj': directory '/home/smithj' does not exist

If any home directories referenced in "/etc/passwd" are returned as not defined, or if any interactive users do not have a home directory assigned, this is a finding.)
  desc 'fix', 'Create home directories to all local interactive users that currently do not have a home directory assigned. Use the following commands to create the user home directory assigned in "/etc/ passwd":

Note: The example will be for the user smithj, who has a home directory of "/home/smithj", a UID of "smithj", and a Group Identifier (GID) of "users" assigned in "/etc/passwd".

# mkdir /home/smithj 
# chown smithj /home/smithj
# chgrp users /home/smithj
# chmod 0750 /home/smithj'
  impact 0.5
  ref 'DPMS Target Oracle Linux 7'
  tag check_id: 'C-36277r622253_chk'
  tag severity: 'medium'
  tag gid: 'V-221728'
  tag rid: 'SV-221728r603789_rule'
  tag stig_id: 'OL07-00-020620'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-36241r602426_fix'
  tag 'documentable'
  tag legacy: ['SV-108299', 'V-99195']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
