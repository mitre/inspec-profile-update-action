control 'SV-76951' do
  title 'Only authenticated system administrators or the designated PKI Sponsor for ColdFusion must have access to ColdFusions private key.'
  desc 'The cornerstone of PKI is the private key used to encrypt or digitally sign information.  If the private key is stolen, this will lead to the compromise of the authentication and non-repudiation gained through PKI because the attacker can use the private key to digitally sign documents and can pretend to be the authorized user.

Both the holders of a digital certificate and the issuing authority must protect the private keys.  Java-based application servers, such as ColdFusion, utilize the Java keystore, which provides storage for cryptographic keys and certificates.  ColdFusion uses the keystore to store private keys for ColdFusion WebSockets and for Flex Integration.'
  desc 'check', 'Within the Administrator Console, navigate to the "Flex Integration" page under the "Data & Services" menu.   If "Enable RMI over SSL for Data Management" is checked, make note of the path and filename of the keystore used.  Navigate to the "WebSocket" page under the "Server Settings" menu.  If "SSL Port" is checked, make note of the keystore path and filename.

Review the permissions on the files designated in the keystore locations specified.  ColdFusion running on Windows should have full control for the Administrators group and the user running ColdFusion on the keystore file.  No other users should have permissions.

If permissions are granted to other users or roles, this is a finding.

If ColdFusion is installed on Linux, the permissions must be 750 or more restrictive with the owner set to the user running the ColdFusion service and a group of root.

If the permissions are more permissive, this is a finding.'
  desc 'fix', %q(Locate the keystore file(s). The location can be found in the Administrator Console within the "Flex Integration" page under the "Data & Services" menu and within the "WebSocket" page under the "Server Settings" menu.  The keystore(s) should have the following permissions:

ColdFusion running on Windows:
1. Right click on the keystore and select "Properties".
2. Click on the "Security" tab and then click the "Advanced" button.
3. On the "Permissions" tab, click the "Disable inheritance" button and select "Remove all inherited permissions from this object." 
4. Click the "Add" button, in the permission Entry dialog, click 'Select a principal."
5. Enter the user that is running the ColdFusion service and give this user Full control and click "OK" to save.
6. Click the "Add" button again, in the permission Entry dialog, click "Select a principal."
7. Enter the Administrators group and give the group Full control and click "OK" to save.
8. Check the checkbox to "Replace all child object permission entries with inheritable permission entries from this object."  
9. Click "OK" to apply these permissions.

ColdFusion running on Linux: 
Use the chmod command to set the permissions correctly and chown to set the owner and group.  For example, if the keystore is named /opt/cf11/jre/lib/security/cacerts and you want to set the owner to cfuser, the commands would be:
     chown cfuser:root /opt/cf11/jre/lib/security/cacerts
     chmod 750 /opt/cf11/jre/lib/security/cacerts)
  impact 0.5
  ref 'DPMS Target ColdFusion 11'
  tag check_id: 'C-63265r1_chk'
  tag severity: 'medium'
  tag gid: 'V-62461'
  tag rid: 'SV-76951r1_rule'
  tag stig_id: 'CF11-04-000138'
  tag gtitle: 'SRG-APP-000176-AS-000125'
  tag fix_id: 'F-68381r2_fix'
  tag 'documentable'
  tag cci: ['CCI-000186']
  tag nist: ['IA-5 (2) (a) (1)']
end
