control 'SV-237234' do
  title 'ColdFusion must remove software components after updated versions have been installed.'
  desc 'Installation of patches and updates is performed when there are errors or security vulnerabilities in the current release of the software.  When previous versions of software components are not removed from the application server after updates have been installed, an attacker may use the older components to exploit the system.

ColdFusion creates a backup directory for an update when installed.  This backup directory allows the SA to uninstall the update if an error occurs or incompatibility is found with the hosted applications.  Once the update is tested and found to work correctly, the backup directory must be removed so that the update cannot be uninstalled.'
  desc 'check', 'Within the Administrator Console, navigate to the "Updates" page under the "Server Update" menu.  Within the "Installed Updates" tab, locate the backup directory location for each update that is installed.  On the server running the ColdFusion server, verify that the backup directories do not exist for any of the updates.

If all updates have been tested/verified and any of the backup directories exist, this is a finding.

Note: Do not remove the backup directory for an update until the update has been tested and verified that the ColdFusion server is operating correctly.'
  desc 'fix', 'Navigate to the "Updates" page under the "Server Update" menu within the Administrator Console.  Within the "Installed Updates" tab, locate the backup directory location for any updates installed.  On the server running the ColdFusion server, remove all backup directories for any updates installed.

Note: Do not remove the backup directory for an update until the update has been tested and verified that the ColdFusion server is operating correctly.'
  impact 0.5
  ref 'DPMS Target Adobe ColdFusion 11'
  tag check_id: 'C-40453r641795_chk'
  tag severity: 'medium'
  tag gid: 'V-237234'
  tag rid: 'SV-237234r641797_rule'
  tag stig_id: 'CF11-06-000225'
  tag gtitle: 'SRG-APP-000454-AS-000268'
  tag fix_id: 'F-40416r641796_fix'
  tag 'documentable'
  tag legacy: ['SV-77031', 'V-62541']
  tag cci: ['CCI-002617']
  tag nist: ['SI-2 (6)']
end
