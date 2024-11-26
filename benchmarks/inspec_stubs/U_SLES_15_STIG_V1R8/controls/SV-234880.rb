control 'SV-234880' do
  title 'All SUSE operating system local interactive user accounts, upon creation, must be assigned a home directory.'
  desc 'If local interactive users are not assigned a valid home directory, there is no place for the storage and control of files they should own.'
  desc 'check', 'Verify all SUSE operating system local interactive users on the system are assigned a home directory upon creation.

Check to see if the system is configured to create home directories for local interactive users with the following command:

> grep -i create_home /etc/login.defs
CREATE_HOME yes

If the value for "CREATE_HOME" parameter is not set to "yes", the line is missing, or the line is commented out, this is a finding.'
  desc 'fix', 'Configure the SUSE operating system to assign home directories to all new local interactive users by setting the "CREATE_HOME" parameter in "/etc/login.defs" to "yes" as follows.

CREATE_HOME yes'
  impact 0.5
  ref 'DPMS Target SUSE Linux Enterprise Server 15'
  tag check_id: 'C-38068r618909_chk'
  tag severity: 'medium'
  tag gid: 'V-234880'
  tag rid: 'SV-234880r622137_rule'
  tag stig_id: 'SLES-15-020110'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-38031r618910_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
