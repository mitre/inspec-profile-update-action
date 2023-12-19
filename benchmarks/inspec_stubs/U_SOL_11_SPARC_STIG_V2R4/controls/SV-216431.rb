control 'SV-216431' do
  title 'Duplicate group names must not exist.'
  desc 'If a group is assigned a duplicate group name, it will create and have access to files with the first GID for that group in group. Effectively, the GID is shared, which is a security risk.'
  desc 'check', 'The root role is required.

Check for duplicate group names.

# getent group | cut -f1 -d":" | sort -n | uniq -d

If output is produced, this is a finding.'
  desc 'fix', 'The root role is required.

Correct or justify any items discovered in the Check step. Determine if there are any duplicate group names, and work with their respective owners to determine the best course of action in accordance with site policy. Delete or change the group name of duplicate groups.'
  impact 0.5
  ref 'DPMS Target Solaris 11 SPARC'
  tag check_id: 'C-17667r622331_chk'
  tag severity: 'medium'
  tag gid: 'V-216431'
  tag rid: 'SV-216431r603868_rule'
  tag stig_id: 'SOL-11.1-070150'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-17665r371382_fix'
  tag 'documentable'
  tag legacy: ['SV-60941', 'V-48069']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
