control 'SV-217171' do
  title 'All SUSE operating system local interactive user accounts, upon creation, must be assigned a home directory.'
  desc 'If local interactive users are not assigned a valid home directory, there is no place for the storage and control of files they should own.'
  desc 'check', 'Verify all SUSE operating system local interactive users on the system are assigned a home directory upon creation.

Check to see if the system is configured to create home directories for local interactive users with the following command:

# grep -i create_home /etc/login.defs
CREATE_HOME yes

If the value for "CREATE_HOME" parameter is not set to "yes", the line is missing, or the line is commented out, this is a finding.'
  desc 'fix', 'Configure the SUSE operating system to assign home directories to all new local interactive users by setting the "CREATE_HOME" parameter in "/etc/login.defs" to "yes" as follows.

CREATE_HOME yes'
  impact 0.5
  ref 'DPMS Target SUSE Linux Enterprise Server 12'
  tag check_id: 'C-18399r369669_chk'
  tag severity: 'medium'
  tag gid: 'V-217171'
  tag rid: 'SV-217171r603262_rule'
  tag stig_id: 'SLES-12-010720'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-18397r369670_fix'
  tag 'documentable'
  tag legacy: ['V-77199', 'SV-91895']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
