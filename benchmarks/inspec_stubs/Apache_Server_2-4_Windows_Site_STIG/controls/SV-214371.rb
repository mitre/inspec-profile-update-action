control 'SV-214371' do
  title 'Only authenticated system administrators or the designated PKI Sponsor for the Apache web server must have access to the Apache web servers private key.'
  desc "The web server's private key is used to prove the identity of the server to clients and securely exchange the shared secret key used to encrypt communications between the web server and clients.

By gaining access to the private key, an attacker can pretend to be an authorized server and decrypt the SSL traffic between a client and the web server."
  desc 'check', 'If the Apache web server does not have a private key, this is Not Applicable.

Review the private key path in the "SSLCertificateFile" directive. Verify only authenticated System Administrators and the designated PKI Sponsor for the web server can access the web server private key.

If the private key is accessible by unauthenticated or unauthorized users, this is a finding.'
  desc 'fix', "Configure the Apache web server to ensure only authenticated and authorized users can access the web server's private key."
  impact 0.5
  ref 'DPMS Target Apache Server 2.4 Windows Site'
  tag check_id: 'C-15582r277854_chk'
  tag severity: 'medium'
  tag gid: 'V-214371'
  tag rid: 'SV-214371r397597_rule'
  tag stig_id: 'AS24-W2-000390'
  tag gtitle: 'SRG-APP-000176-WSR-000096'
  tag fix_id: 'F-15580r277855_fix'
  tag 'documentable'
  tag legacy: ['SV-102607', 'V-92519']
  tag cci: ['CCI-000186']
  tag nist: ['IA-5 (2) (a) (1)']
end
