control 'SV-234991' do
  title 'All SUSE operating system local interactive users must have a home directory assigned in the /etc/passwd file.'
  desc 'If local interactive users are not assigned a valid home directory, there is no place for the storage and control of files they should own.'
  desc 'check', %q(Verify SUSE operating system local interactive users on the system have a home directory assigned.

Check for missing local interactive user home directories with the following command:

> sudo pwck -r
user 'smithj': directory '/home/smithj' does not exist

Ask the System Administrator (SA) if any users found without home directories are local interactive users. If the SA is unable to provide a response, check for users with a User Identifier (UID) of 1000 or greater with the following command:

> awk -F: '($3>=1000)&&($1!="nobody"){print $1 ":" $3}' /etc/passwd

If any interactive users do not have a home directory assigned, this is a finding.)
  desc 'fix', 'Assign home directories to all SUSE operating system local interactive users that currently do not have a home directory assigned.

Assign a home directory to users via the usermod command:

> sudo usermod -d /home/smithj smithj'
  impact 0.5
  ref 'DPMS Target SUSE Linux Enterprise Server 15'
  tag check_id: 'C-38179r619242_chk'
  tag severity: 'medium'
  tag gid: 'V-234991'
  tag rid: 'SV-234991r622137_rule'
  tag stig_id: 'SLES-15-040070'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-38142r619243_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
