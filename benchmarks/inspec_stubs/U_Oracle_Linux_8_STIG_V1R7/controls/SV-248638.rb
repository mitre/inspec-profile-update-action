control 'SV-248638' do
  title 'All OL 8 local interactive users must have a home directory assigned in the "/etc/passwd" file.'
  desc 'If local interactive users are not assigned a valid home directory, there is no place for the storage and control of files they should own.'
  desc 'check', "Verify local interactive users on OL 8 have a home directory assigned with the following command: 
 
$ sudo pwck -r 
 
user 'lp': directory '/var/spool/lpd' does not exist 
user 'news': directory '/var/spool/news' does not exist 
user 'uucp': directory '/var/spool/uucp' does not exist 
user 'www-data': directory '/var/www' does not exist 
 
Ask the System Administrator (SA) if any users found without home directories are local interactive users.  
 
If the SA is unable to provide a response, check for users with a User Identifier (UID) of 1000 or greater with the following command: 
 
$ sudo awk -F: '($3>=1000)&&($7 !~ /nologin/){print $1, $3, $6}' /etc/passwd
 
If any interactive users do not have a home directory assigned, this is a finding."
  desc 'fix', 'Assign home directories to all local interactive users on OL 8 that currently do not have a home directory assigned.'
  impact 0.5
  ref 'DPMS Target Oracle Linux 8'
  tag check_id: 'C-52072r779478_chk'
  tag severity: 'medium'
  tag gid: 'V-248638'
  tag rid: 'SV-248638r779480_rule'
  tag stig_id: 'OL08-00-010720'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-52026r779479_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
