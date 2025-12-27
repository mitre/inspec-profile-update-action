control 'SV-54308' do
  title 'Only authenticated system administrators or the designated PKI Sponsor for the web server must have access to the web servers private key.'
  desc "The web server's private key is used to prove the identity of the server to clients and securely exchange the shared secret key used to encrypt communications between the web server and clients.

By gaining access to the private key, an attacker can pretend to be an authorized server and decrypt the SSL traffic between a client and the web server."
  desc 'check', 'If the web server does not have a private key, this is N/A. 

Review the web server documentation and deployed configuration to determine whether only authenticated system administrators and the designated PKI Sponsor for the web server can access the web server private key.

If the private key is accessible by unauthenticated or unauthorized users, this is a finding.'
  desc 'fix', "Configure the web server to ensure only authenticated and authorized users can access the web server's private key."
  impact 0.5
  ref 'DPMS Target SRG-APP-WSR'
  tag check_id: 'C-48128r2_chk'
  tag severity: 'medium'
  tag gid: 'V-41731'
  tag rid: 'SV-54308r3_rule'
  tag stig_id: 'SRG-APP-000176-WSR-000096'
  tag gtitle: 'SRG-APP-000176-WSR-000096'
  tag fix_id: 'F-47190r2_fix'
  tag 'documentable'
  tag cci: ['CCI-000186']
  tag nist: ['IA-5 (2) (a) (1)']
end
