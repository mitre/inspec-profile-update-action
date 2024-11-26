control 'SV-76865' do
  title 'The ColdFusion log information must be protected from any type of unauthorized read access through the Administrator Console.'
  desc 'Allowing any user to view log messages provides information to individuals that may be used to compromise the system.  This information may provide system design, user access/IP addresses, interconnected systems, and security settings such as encryption used and version numbers.  Controlling read access to this data, either through the Administrator Console or through the OS, must be controlled or limited to only those individuals who need access to fulfill their responsibilities.'
  desc 'check', 'Review the roles assigned to the defined users within the "User Manager" page under the "Security" menu.  Only users given the responsibility to read logs should have the following role assigned:
Debugging and Logging>Logging

If any user, other than those assigned to read logs, is assigned this role, this is a finding.'
  desc 'fix', 'Enable the Debugging and Logging>Logging role for those users that require the ability to read log files.  This parameter is set in the "User Manager" page under the "Security" menu.'
  impact 0.5
  ref 'DPMS Target ColdFusion 11'
  tag check_id: 'C-63179r1_chk'
  tag severity: 'medium'
  tag gid: 'V-62375'
  tag rid: 'SV-76865r1_rule'
  tag stig_id: 'CF11-02-000049'
  tag gtitle: 'SRG-APP-000118-AS-000078'
  tag fix_id: 'F-68295r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000162']
  tag nist: ['AU-9 a']
end
