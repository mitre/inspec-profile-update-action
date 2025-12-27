control 'SV-237154' do
  title 'The ColdFusion log information must be protected from any type of unauthorized deletion through the Administrator Console.'
  desc 'When a system is attacked, one of the tasks of the attacker is to cover his tracks by deleting log files or log data.  This enables the attacker to go unnoticed and to make later forensic analysis of the attack difficult, if not impossible.  To protect the log information from deletion and discover the attacker quickly, the log files must be protected.  This protection must take place at both the Administrator Console and at the OS level.  Within the Administrator Console, the protection can be performed by giving users the proper roles and only giving log deletion to those that need that capability to perform their job duties.  At the OS level, protecting the logs from deletion is performed by assigned the proper privileges to the log files and also giving OS users limited roles.'
  desc 'check', 'Review the roles assigned to the defined users within the "User Manager" page under the "Security" menu.  Only users given the responsibility to delete logs should have the Debugging and Logging>Logging role assigned.

If any user, other than those assigned the capability to delete logs, is assigned this role, this is a finding.'
  desc 'fix', 'Enable the Debugging and Logging>Logging role for those users that require the ability to delete log files.  This parameter is set in the "User Manager" page under the "Security" menu.'
  impact 0.5
  ref 'DPMS Target Adobe ColdFusion 11'
  tag check_id: 'C-40373r641555_chk'
  tag severity: 'medium'
  tag gid: 'V-237154'
  tag rid: 'SV-237154r641557_rule'
  tag stig_id: 'CF11-02-000052'
  tag gtitle: 'SRG-APP-000120-AS-000080'
  tag fix_id: 'F-40336r641556_fix'
  tag 'documentable'
  tag legacy: ['SV-76871', 'V-62381']
  tag cci: ['CCI-000164']
  tag nist: ['AU-9 a']
end
