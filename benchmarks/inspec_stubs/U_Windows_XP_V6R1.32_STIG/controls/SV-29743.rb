control 'SV-29743' do
  title 'The system does not have a backup administrator account'
  desc 'This check verifies that a backup administrator account has been created to ensure system availability in the event that no administrators are able or available to access the system.  The built-in administrator account may be used for this purpose.  The IAO will ensure the backup administrator account is stored in a secure location.'
  desc 'check', 'Interview the SA to determine if a backup administrator account exists and is stored with its password in a secure location.'
  desc 'fix', 'Create and maintain a backup administrator account for emergency situations.'
  impact 0.5
  ref 'DPMS Target Windows XP'
  tag check_id: 'C-11570r1_chk'
  tag severity: 'medium'
  tag gid: 'V-14224'
  tag rid: 'SV-29743r2_rule'
  tag gtitle: 'Backup Administrator Account'
  tag fix_id: 'F-13548r2_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag ia_controls: 'ECPA-1'
end
