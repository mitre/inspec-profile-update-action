control 'SV-235987' do
  title 'Oracle WebLogic must protect the confidentiality of applications and leverage transmission protection mechanisms, such as TLS and SSL VPN, when deploying applications.'
  desc 'Preventing the disclosure of transmitted information requires that applications take measures to employ some form of cryptographic mechanism in order to protect the information during transmission. This is usually achieved through the use of Transport Layer Security (TLS), SSL VPN, or IPSEC tunnel. 

If the application server does not protect the application files that are created before and during the application deployment process, there is a risk that the application could be compromised prior to deployment.'
  desc 'check', "1. Access AC
2. From 'Domain Structure', select 'Environment' -> 'Servers' 
3. From the list of servers, select the AdminServer
4. From 'Configuration' tab -> 'General' tab, ensure 'Listen Port Enabled' checkbox is deselected
5. Ensure 'SSL Listen Port Enabled' checkbox is selected and a valid port number is in 'SSL Listen Port' field, e.g., 7002


If the field 'SSL Listen Port Enabled' is not selected or 'Listen Port Enabled' is selected, this is a finding."
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
  tag check_id: 'C-39206r628737_chk'
  tag severity: 'medium'
  tag gid: 'V-235987'
  tag rid: 'SV-235987r628739_rule'
  tag stig_id: 'WBLC-08-000231'
  tag gtitle: 'SRG-APP-000440-AS-000167'
  tag fix_id: 'F-39169r628738_fix'
  tag 'documentable'
  tag legacy: ['SV-70583', 'V-56329']
  tag cci: ['CCI-002421']
  tag nist: ['SC-8 (1)']
end
