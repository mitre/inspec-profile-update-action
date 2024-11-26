control 'SV-89645' do
  title 'WebGUI access to the MQ Appliance network device must map the authenticated identity to the user account for PKI-based authentication.'
  desc 'Authorization for access to any MQ Appliance network device requires an approved and assigned individual account identifier. To ensure only the assigned individual is using the account, the account must be bound to a user certificate when PKI-based authentication is implemented.'
  desc 'check', 'Log on to the MQ Appliance CLI as a privileged user. Verify the MQ Appliance is configured to support PKI-based user authentication. 

Verify an SSL Server Profile is associated with the WebGUI (CLI). Enter: 
co 
show web-mgmt 

[Note the name of the ssl-server] 

Display the parameters of the ssl-server (CLI). Enter: 
co 
crypto 
ssl-server <ssl-server name> 
show 

[Note the name of the valcred] 

Display the certificates in the ValCred (CLI). Enter: 
co 
crypto 
valcred <name of valcred> 
show 

Verify all listed client certificates are authorized to access the MQ Appliance. 

If any are not authorized, this is a finding. 

Spot-check access to the appliance: 

Attempt to access the appliance from a browser enabled with an authorized certificate. 

If authorized access does not succeed, this is a finding. 

Attempt to access the appliance from a browser not enabled with an authorized client certificate. 

If unauthorized access succeeds, this is a finding.'
  desc 'fix', 'Log on to the MQ Appliance CLI as a privileged user. Configure MQ Appliance to support PKI-based user authentication. 

Assign the WebGUI to one management port (CLI). Enter: 
co 
web-mgmt <mgmt port IP addr> 9090 <timeout in seconds> 
write mem 
y 

Import to cert directory MQ Appliance private key and cert and client cert(s) (WebGUI): 
- Log on to the WebGUI as a privileged user. 
- Click on the Administration (gear) icon. 
- Under Main, click on File Management. 
- Click cert directory. 
- Click Actions. 
- Upload files. 
- Browse to select MQ Appl privkey. 
- Add. 
- Browse to select MQ Appl cert. 
- Add. 
- Browse to select client cert. 
- Add. 
- [Repeat Browse and Add for all desired client certs.] 
- Upload. 
- Continue, 

Create cert aliases (CLI). Enter: 
co 
crypto 
certificate <MQAppl CryptoCert alias: appliance name> cert:///<MQAppl cert file name> 
certificate <client CryptoCert alias: subject field fm client cert> cert:///<client cert file name> 
[Repeat certificate command for any additional client certs.] 
exit 
write mem 
y 

Create MQAppl private key alias (CLI). Enter: 
co 
crypto 
key <MQAppl CryptoKey alias> cert:///<MQAppl privkey file name> 
exit 
write mem 
y 

Create MQAppl ID Credential (CLI). Enter: 
co 
crypto 
idcred <MQAppl IDCred name> <MQAppl CryptoKey alias> <MQAppl CryptoCert alias> 
exit 
write mem 
y 

Create a client Validation Credential (CLI). Enter: 
co 
crypto 
valcred <Client ValCred name> 
certificate <Client CryptoCert alias> 
[Add additional client certificates as required.] 
exit 
exit 
write mem 
y 

Create SSL Server Profile (CLI). Enter: 
co 
crypto 
ssl-server <SSL Svr Profile name> 
admin-state enabled 
idcred <MQAppl IDCred name> 
protocols TLSv1d2 
valcred <Client ValCred name> 
request-client-auth on 
require-client-auth on 
send-client-auth-ca-list on 
exit 
exit 
write mem 
y 

Associate SSL Server Profile with WebGUI (CLI). Enter: 
co 
web-mgmt 
ssl-config-type server 
ssl-server <SSL Svr Profile name> 
exit 
write mem 
y'
  impact 0.5
  ref 'DPMS Target IBM MQ Appliance v9.0 NDM'
  tag check_id: 'C-74823r1_chk'
  tag severity: 'medium'
  tag gid: 'V-74971'
  tag rid: 'SV-89645r1_rule'
  tag stig_id: 'MQMH-ND-000690'
  tag gtitle: 'SRG-APP-000177-NDM-000263'
  tag fix_id: 'F-81587r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000187']
  tag nist: ['IA-5 (2) (a) (2)']
end
