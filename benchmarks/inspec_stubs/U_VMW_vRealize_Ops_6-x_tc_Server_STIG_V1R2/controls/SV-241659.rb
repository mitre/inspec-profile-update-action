control 'SV-241659' do
  title 'tc Server ALL must only allow authenticated system administrators to have access to the truststore.'
  desc "The web server's private key is used to prove the identity of the server to clients and securely exchange the shared secret key used to encrypt communications between the web server and clients.

By gaining access to the private key, an attacker can pretend to be an authorized server and decrypt the SSL traffic between a client and the web server.

As a Tomcat derivative tc Server is designed to store the server's private key in a keystore file. An important vROps keystore file is “tcserver.truststore”, and this file must be protected to only allow system administrators and other authorized users to have access to it."
  desc 'check', 'At the command prompt, execute the following command:

ls -al /storage/vcops/user/conf/ssl/tcserver.truststore

Verify that file permissions are set to “640” or more restrictive. 

Verify that the owner and group-owner are set to admin. If either of these conditions are not met, this is a finding.'
  desc 'fix', 'At the command prompt, execute the following commands:

chown admin:admin /storage/vcops/user/conf/ssl/tcserver.truststore

chmod 640 /storage/vcops/user/conf/ssl/tcserver.truststore'
  impact 0.5
  ref 'DPMS Target VMware vRealize Operations Manager 6-x tc Server'
  tag check_id: 'C-44935r684167_chk'
  tag severity: 'medium'
  tag gid: 'V-241659'
  tag rid: 'SV-241659r879613_rule'
  tag stig_id: 'VROM-TC-000470'
  tag gtitle: 'SRG-APP-000176-WSR-000096'
  tag fix_id: 'F-44894r683838_fix'
  tag 'documentable'
  tag legacy: ['SV-99603', 'V-88953']
  tag cci: ['CCI-000186']
  tag nist: ['IA-5 (2) (a) (1)']
end
