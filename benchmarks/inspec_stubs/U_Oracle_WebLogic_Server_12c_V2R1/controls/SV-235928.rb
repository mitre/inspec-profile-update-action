control 'SV-235928' do
  title 'Oracle WebLogic must utilize cryptography to protect the confidentiality of remote access management sessions.'
  desc 'Remote management access is accomplished by leveraging common communication protocols and establishing a remote connection to the application server via a network for the purposes of managing the application server. If cryptography is not used, then the session data traversing the remote connection could be intercepted and compromised. 

Types of management interfaces utilized by an application server include web-based HTTPS interfaces as well as command line-based management interfaces. All application server management interfaces must utilize cryptographic encryption.'
  desc 'check', "1. Access AC
2. From 'Domain Structure', select 'Environment' -> 'Servers' 
3. From the list of servers, select one which needs check for SSL configuration verification
4. From 'Configuration' tab -> 'General' tab, ensure 'Listen Port Enabled' checkbox is deselected
5. Ensure 'SSL Listen Port Enabled' checkbox is selected and a valid port number is in 'SSL Listen Port' field, e.g., 7002

6 Repeat steps 3-5 for all servers requiring SSL configuration checking

If 'Listen Port Enabled' is selected, this is a finding.
If 'SSL Listen Port Enabled' is not selected, this is a finding."
  desc 'fix', "1. Obtain an identity (private key and digital certificates) and trust (certificates of trusted certificate authorities) to configure on the server
2. Create Identity keystore and load private key and certificate using ImportPrivateKey java utility, example:
$ java utils.ImportPrivateKey -certfile <cert_file> -keyfile <private_key_file> [-keyfilepass <private_key_password>] -keystore <keystore> -storepass <storepass> [-storetype <storetype>] -alias <alias> [-keypass <keypass>] 
3. Access AC
4. Utilize 'Change Center' to create a new change session
5. From 'Domain Structure', select 'Environment' -> 'Servers' 
6. From the list of servers, select one which needs SSL set up
7. From 'Configuration' tab -> 'General' tab, deselect 'Listen Port Enabled' checkbox
8. Select 'SSL Listen Port Enabled' checkbox and enter a valid port number in 'SSL Listen Port' field, e.g., 7002
9. From 'Configuration' tab -> 'Keystores' tab, click 'Change' button in 'Keystores' section
10. From dropdown, select 'Custom Identity and Java Standard Trust' and click 'Save'
11. Enter the fully qualified path to Identity keystore, from step 2, in 'Custom Identity Keystore' field
12. Enter 'JKS' in the 'Custom Identity Keystore Type' field
13. Enter the Identity keystore password in 'Custom Identity Keystore Passphrase' and 'Confirm Custom Identity Keystore Passphrase' fields
14. Enter the Java Standard Trust keystore (cacerts) password in 'Java Standard Trust Keystore Passphrase' and 'Confirm Java Standard Trust Keystore Passphrase' fields
15. Leave all other fields blank and click 'Save'
16. From 'Configuration' tab -> 'SSL' tab, enter values from step 2 into corresponding fields, as follows:
- Enter <alias> into 'Private Key Alias'
- Enter <private_key_password> into 'Private Key Passphrase'
- Enter <private_key_password> into 'Confirm Private Key Passphrase'
17. Click 'Save', and from 'Change Center' click 'Activate Changes' to enable configuration changes
18. Repeat steps 4-17 for all servers requiring SSL configuration
19. From 'Domain Structure', select 'Environment' -> 'Servers', click 'Control' tab
20. Select checkbox for all servers configured in previous steps and click 'Restart SSL'"
  impact 0.5
  ref 'DPMS Target Oracle WebLogic Server 12c'
  tag check_id: 'C-39147r628560_chk'
  tag severity: 'medium'
  tag gid: 'V-235928'
  tag rid: 'SV-235928r628562_rule'
  tag stig_id: 'WBLC-01-000009'
  tag gtitle: 'SRG-APP-000014-AS-000009'
  tag fix_id: 'F-39110r628561_fix'
  tag 'documentable'
  tag legacy: ['SV-70459', 'V-56205']
  tag cci: ['CCI-000068']
  tag nist: ['AC-17 (2)']
end
