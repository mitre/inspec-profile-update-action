control 'SV-44998' do
  title 'The /etc/group file must have mode 0644 or less permissive.'
  desc 'The /etc/group file is critical to system security and must be protected from unauthorized modification.  The group file contains a list of system groups and associated information.'
  desc 'check', 'Check the mode of the /etc/group file.
# ls -l /etc/group
If the file mode is more permissive than 0644, this is a finding.'
  desc 'fix', 'Change the mode of the /etc/group file to 0644 or less permissive.
# chmod 0644 /etc/group'
  impact 0.5
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-42403r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22337'
  tag rid: 'SV-44998r1_rule'
  tag stig_id: 'GEN001393'
  tag gtitle: 'GEN001393'
  tag fix_id: 'F-38413r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
