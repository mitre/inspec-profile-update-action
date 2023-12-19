control 'SV-234992' do
  title 'All SUSE operating system local interactive user home directories defined in the /etc/passwd file must exist.'
  desc 'If a local interactive user has a home directory defined that does not exist, the user may be given access to the / directory as the current working directory upon logon. This could create a Denial of Service because the user would not be able to access their logon configuration files, and it may give them visibility to system files they normally would not be able to access.'
  desc 'check', %q(Verify the assigned home directory of all SUSE operating system local interactive users on the system exists.

Check the home directory assignment for all local interactive non-privileged users on the system with the following command:

> awk -F: '($3>=1000)&&($7 !~ /nologin/){print $1, $6}' /etc/passwd

smithj /home/smithj

Note: This may miss interactive users that have been assigned a privileged User Identifier (UID). Evidence of interactive use may be obtained from a number of log files containing system logon information.

Check that all referenced home directories exist with the following command:

> sudo pwck -r

user 'smithj': directory '/home/smithj' does not exist

If any home directories referenced in "/etc/passwd" are returned as not defined, this is a finding.)
  desc 'fix', 'Create home directories to all SUSE operating system local interactive users that currently do not have a home directory assigned. Use the following commands to create the user home directory assigned in "/etc/ passwd":

Note: The example will be for the user smithj, who has a home directory of "/home/smithj", a UID of "smithj", and a Group Identifier (GID) of "users assigned" in "/etc/passwd".

> sudo mkdir /home/smithj 
> sudo chown smithj /home/smithj
> sudo chgrp users /home/smithj
> sudo chmod 0750 /home/smithj'
  impact 0.5
  ref 'DPMS Target SUSE Linux Enterprise Server 15'
  tag check_id: 'C-38180r619245_chk'
  tag severity: 'medium'
  tag gid: 'V-234992'
  tag rid: 'SV-234992r622137_rule'
  tag stig_id: 'SLES-15-040080'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-38143r619246_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
