control 'SV-217170' do
  title 'All SUSE operating system local interactive users must have a home directory assigned in the /etc/passwd file.'
  desc 'If local interactive users are not assigned a valid home directory, there is no place for the storage and control of files they should own.'
  desc 'check', "Verify SUSE operating system local interactive users on the system have a home directory assigned.

Check for missing local interactive user home directories with the following command:

> sudo pwck -r
user 'smithj': directory '/home/smithj' does not exist

Ask the System Administrator (SA) if any users found without home directories are local interactive users. If the SA is unable to provide a response, check for users with a User Identifier (UID) of 1000 or greater with the following command:

> sudo awk -F: '($3>=1000)&&($7 !~ /nologin/){print $1, $3, $6}' /etc/passwd

If any interactive users do not have a home directory assigned, this is a finding."
  desc 'fix', 'Assign home directories to all SUSE operating system local interactive users that currently do not have a home directory assigned.

Assign a home directory to users via the usermod command:

> sudo usermod -d /home/smithj smithj'
  impact 0.5
  ref 'DPMS Target SUSE Linux Enterprise Server 12'
  tag check_id: 'C-18398r646726_chk'
  tag severity: 'medium'
  tag gid: 'V-217170'
  tag rid: 'SV-217170r646728_rule'
  tag stig_id: 'SLES-12-010710'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-18396r646727_fix'
  tag 'documentable'
  tag legacy: ['SV-91893', 'V-77197']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
