control 'SV-89621' do
  title 'When connecting to the MQ Appliance network device using the WebGUI, it must implement replay-resistant authentication mechanisms for network access to privileged accounts.'
  desc 'A replay attack may enable an unauthorized user to gain access to the MQ Appliance. Authentication sessions between the authenticator and the application validating the user credentials must not be vulnerable to a replay attack. 

An authentication process resists replay attacks if it is impractical to achieve a successful authentication by recording and replaying a previous authentication message. 

Techniques used to address this include protocols using nonces (e.g., numbers generated for a specific one-time use) or challenges (e.g., TLS, WS_Security). Additional techniques include time-synchronous or challenge-response one-time authenticators.'
  desc 'check', 'Log on to the MQ Appliance CLI as a privileged user. Verify the MQ Appliance PKI-based user authentication is configured to support multifactor authentication to provide replay-resistant authentication. 

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

If any are not authorized, this is a finding.'
  desc 'fix', 'Log on to the MQ Appliance CLI as a privileged user. 

Configure MQ Appliance PKI-based user multifactor authentication to provide replay-resistant authentication. 

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
- Continue. 

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
[Add additional client certificates as required] 
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
  tag check_id: 'C-74805r1_chk'
  tag severity: 'medium'
  tag gid: 'V-74947'
  tag rid: 'SV-89621r1_rule'
  tag stig_id: 'MQMH-ND-000530'
  tag gtitle: 'SRG-APP-000156-NDM-000250'
  tag fix_id: 'F-81563r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001941']
  tag nist: ['IA-2 (8)']
end
