control 'SV-237165' do
  title 'ColdFusion must protect software libraries from being changed by OS users.'
  desc 'Controlling the overall security posture of the server encompasses controlling the patches and versions of the software running within the production environment.  Patches are installed to fix security and bug issues.  Vendors will often supply a feature to uninstall the patch in the event the patch does not install correctly,  if the patch causes issues with hosted applications, or if the patch contains issues not found during testing.  The uninstall feature is meant to be used by an SA to maintain a secure and stable system.  In the event an attacker gains access to the uninstall functionality, he can then attempt to revert the system to an unsecure version which may have known and documented attacks that can be successful to compromise ColdFusion.  

To protect against this type of attack and to further define roles for users, access to the patch management functionality is important.  Proper protection is performed through assigning the appropriate roles to the users of the Administrator Console and through the least privileged permissions assigned at the OS level.'
  desc 'check', 'Locate the hf-updates directory for ColdFusion.  Review the permissions on the hf-updates directory.  ColdFusion running on Windows should have full control for the Administrators group and the user running the ColdFusion application.  No other users or groups should have permissions.

If permissions are granted to other users or groups, this is a finding.

If ColdFusion is installed on Linux, the permissions must be "750" or more restrictive with the owner set to the user running the ColdFusion service and a group of root.

If the permissions are more permissive, this is a finding.'
  desc 'fix', 'Locate the hf-updates directory for ColdFusion.  The hf-updates directory should have the following permissions:

ColdFusion running on Windows:
1. Right click on the "hf-updates" directory and select "Properties".
2. Click on the "Security" tab and then click the "Advanced" button.
3. On the "Permissions" tab, click the "Disable inheritance" button and select "Remove all inherited permissions from this object."
4. Click the "Add" button, in the permission Entry dialog, click "Select a principal."
5. Enter the user that is running the ColdFusion service and give this user Full control and click "OK" to save.
6. Click the "Add" button again, in the permission Entry dialog, click "Select a principal."
7. Enter the Administrators group and give the group Full control and click "OK" to save.
8. Check the checkbox to "Replace all child object permission entries with inheritable permission entries from this object."
9. Click "OK" to apply these permissions.

ColdFusion running on Linux: 
Use the chmod command to set the permissions correctly and chown to set the owner and group.  For example, if the hf-updates directory is found at /opt/cf11/cfusion/hf-updates and you want to set the owner to cfuser, the commands would be:
     chown cfuser:root /opt/cf11/cfusion/hf-updates
     chmod 750 /opt/cf11/cfusion/hf-updates'
  impact 0.5
  ref 'DPMS Target Adobe ColdFusion 11'
  tag check_id: 'C-40384r641588_chk'
  tag severity: 'medium'
  tag gid: 'V-237165'
  tag rid: 'SV-237165r641590_rule'
  tag stig_id: 'CF11-03-000093'
  tag gtitle: 'SRG-APP-000133-AS-000092'
  tag fix_id: 'F-40347r641589_fix'
  tag 'documentable'
  tag legacy: ['SV-76893', 'V-62403']
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']
end
