control 'SV-237162' do
  title 'The ColdFusion log information must be protected from any type of unauthorized deletion by having file ownership set properly.'
  desc 'When a system is attacked, one of the tasks of the attacker is to cover his tracks by deleting log files or log data.  This enables the attacker to go unnoticed and to make later forensic analysis of the attack difficult, if not impossible.  To protect the log information from deletion and discover the attacker quickly, the log files must be protected.  This protection must take place at both the Administrator Console and at the OS level.  Within the Administrator Console, the protection can be performed by giving users the proper roles and only giving log deletion to those that need that capability to perform their job duties.  At the OS level, protecting the logs from deletion is performed by assigned the proper privileges to the log files and also giving OS users limited roles.'
  desc 'check', 'Locate the logs directory for ColdFusion. The location can be found in the Administrator Console within the "Logging Settings" page under the "Debugging & Logging" menu.  The log directory and log files should have the following permissions:

ColdFusion running on Windows should have full control for the Administrators group and the user running ColdFusion.  No other users should have permissions.

ColdFusion running on Linux must have group ownership set to "root" and the owner set to the user running ColdFusion.

If the ownership of the log directory and log files is incorrect, this is a finding.'
  desc 'fix', 'Locate the logs directory for ColdFusion. The location can be found in the Administrator Console within the "Logging Settings" page under the "Debugging & Logging" menu.  The log directory and log file permissions can be set by:

ColdFusion running on Windows:
1. Right click on the logs directory for ColdFusion and select "Properties".
2. Click on the "Security" tab and then click the "Advanced" button.
3. On the "Permissions" tab, click the "Disable inheritance" button and select "Remove all inherited permissions from this object." 
4. Click the "Add" button, in the permission Entry dialog, click "Select a principal."
5. Enter the user that is running the ColdFusion service and give this user Full control and click "OK" to save.
6. Click the "Add" button again, in the permission Entry dialog, click "Select a principal."
7. Enter the Administrators group and give the group Full control and click "OK" to save.
8. Check the checkbox to "Replace all child object permission entries with inheritable permission entries from this object."  
9. Click "OK" to apply these permissions.

ColdFusion running on Linux: 
Use the chown command to set the owner and group.  For example, if the log directory is located at /opt/cf11/cfusion/logs and the owner is to be cfuser, the command would be:
     chown -R cfuser:root /opt/cf11/cfusion/logs'
  impact 0.5
  ref 'DPMS Target Adobe ColdFusion 11'
  tag check_id: 'C-40381r641579_chk'
  tag severity: 'medium'
  tag gid: 'V-237162'
  tag rid: 'SV-237162r641581_rule'
  tag stig_id: 'CF11-02-000082'
  tag gtitle: 'SRG-APP-000120-AS-000080'
  tag fix_id: 'F-40344r641580_fix'
  tag 'documentable'
  tag legacy: ['SV-76887', 'V-62397']
  tag cci: ['CCI-000164']
  tag nist: ['AU-9 a']
end
