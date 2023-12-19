control 'SV-237161' do
  title 'The ColdFusion log information must be protected from any type of unauthorized modification by having file ownership set properly.'
  desc "Allowing any user to modify log messages provides a method for an attacker to hide his attack and go unnoticed.  Log modification also makes forensic investigation difficult, if not impossible, as the information needed to recreate the event is either deleted or modified to hide what actions took place.  Users are unable to modify log data through the Administrator Console, so the protection from modification is only relevant by enforcing protections from modification at the OS level.  This is performed by properly setting file permissions and enforcing user logons that match each user's job role."
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
  tag check_id: 'C-40380r641576_chk'
  tag severity: 'medium'
  tag gid: 'V-237161'
  tag rid: 'SV-237161r641578_rule'
  tag stig_id: 'CF11-02-000081'
  tag gtitle: 'SRG-APP-000119-AS-000079'
  tag fix_id: 'F-40343r641577_fix'
  tag 'documentable'
  tag legacy: ['SV-76885', 'V-62395']
  tag cci: ['CCI-000163']
  tag nist: ['AU-9 a']
end
