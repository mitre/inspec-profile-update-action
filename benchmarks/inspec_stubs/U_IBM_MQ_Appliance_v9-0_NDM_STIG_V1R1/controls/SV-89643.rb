control 'SV-89643' do
  title 'WebGUI access to the MQ Appliance network device, when using PKI-based authentication, must validate certificates by constructing a certification path (which includes status information) to an accepted trust anchor.'
  desc 'Without path validation, an informed trust decision by the relying party cannot be made when presented with any certificate not already explicitly trusted. 

A trust anchor is an authoritative entity represented via a public key and associated data. It is used in the context of public key infrastructures, X.509 digital certificates, and DNSSEC. 

When there is a chain of trust, usually the top entity to be trusted becomes the trust anchor; it can be, for example, a Certification Authority (CA). A certification path starts with the subject certificate and proceeds through a number of intermediate certificates up to a trusted root certificate, typically issued by a trusted CA. 

This requirement verifies that a certification path to an accepted trust anchor is used for certificate validation and that the path includes status information. Path validation is necessary for a relying party to make an informed trust decision when presented with any certificate not already explicitly trusted. Status information for certification paths includes certificate revocation lists or online certificate status protocol responses. Validation of the certificate status information is out of scope for this requirement.'
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

If any listed client certificates are not authorized to access the MQ Appliance, this is a finding.'
  desc 'fix', 'Log on to the MQ Appliance CLI as a privileged user. Configure MQ Appliance to support PKI-based user authentication. 

Assign the WebGUI to one management port (CLI). Enter: 
co 
web-mgmt <mgmt port IP addr> 9090 <timeout in seconds> 
write mem 
y 

Import to cert directory MQ Appliance private key and cert, and client cert(s) (WebGUI): 
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
  tag check_id: 'C-74821r1_chk'
  tag severity: 'medium'
  tag gid: 'V-74969'
  tag rid: 'SV-89643r1_rule'
  tag stig_id: 'MQMH-ND-000670'
  tag gtitle: 'SRG-APP-000175-NDM-000262'
  tag fix_id: 'F-81585r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000185']
  tag nist: ['IA-5 (2) (b) (1)']
end
