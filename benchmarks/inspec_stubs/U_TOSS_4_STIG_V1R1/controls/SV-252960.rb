control 'SV-252960' do
  title 'All TOSS local interactive user accounts must be assigned a home directory upon creation.'
  desc 'If local interactive users are not assigned a valid home directory, there is no place for the storage and control of files they should own.'
  desc 'check', 'Verify all local interactive users on TOSS are assigned a home directory upon creation with the following command:

$ sudo grep -i create_home /etc/login.defs

CREATE_HOME yes

If the value for "CREATE_HOME" parameter is not set to "yes", the line is missing, or the line is commented out, this is a finding.'
  desc 'fix', 'Configure TOSS to assign home directories to all new local interactive users by setting the "CREATE_HOME" parameter in "/etc/login.defs" to "yes" as follows.

CREATE_HOME yes'
  impact 0.5
  ref 'DPMS Target TOSS 4'
  tag check_id: 'C-56413r824202_chk'
  tag severity: 'medium'
  tag gid: 'V-252960'
  tag rid: 'SV-252960r824204_rule'
  tag stig_id: 'TOSS-04-020200'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-56363r824203_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
