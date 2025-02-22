control 'SV-216430' do
  title 'Duplicate user names must not exist.'
  desc 'If a user is assigned a duplicate user name, it will create and have access to files with the first UID for that username in passwd.'
  desc 'check', "The root role is required.

Identify any duplicate user names.

# getent passwd | awk -F: '{print $1}' | uniq -d

If output is produced, this is a finding."
  desc 'fix', 'The root role is required.

Correct or justify any items discovered in the Check step. Determine if there are any duplicate user names, and work with their respective owners to determine the best course of action in accordance with site policy. Delete or change the user name of duplicate users.'
  impact 0.5
  ref 'DPMS Target Solaris 11 SPARC'
  tag check_id: 'C-17666r371378_chk'
  tag severity: 'medium'
  tag gid: 'V-216430'
  tag rid: 'SV-216430r603267_rule'
  tag stig_id: 'SOL-11.1-070140'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-17664r371379_fix'
  tag 'documentable'
  tag legacy: ['V-48073', 'SV-60945']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
