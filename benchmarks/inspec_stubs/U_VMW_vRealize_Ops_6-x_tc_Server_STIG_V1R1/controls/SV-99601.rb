control 'SV-99601' do
  title 'tc Server ALL must only allow authenticated system administrators to have access to the keystore.'
  desc "The web server's private key is used to prove the identity of the server to clients and securely exchange the shared secret key used to encrypt communications between the web server and clients.

By gaining access to the private key, an attacker can pretend to be an authorized server and decrypt the SSL traffic between a client and the web server.

tc Server stores the server's private key in a keystore file. The vROps keystore file is “tcserver.keystore”, and this file must be protected to only allow system administrators and other authorized users to have access to it."
  desc 'check', 'At the command prompt, execute the following command:

ls -al /storage/vcops/user/conf/ssl/tcserver.keystore

Verify that file permissions are set to “640” or more restrictive. 

Verify that the owner and group-owner are set to admin. If either of these conditions are not met, this is a finding.'
  desc 'fix', 'At the command prompt, execute the following commands:

chown admin:admin /storage/vcops/user/conf/ssl/tcserver.keystore

chmod 640 /storage/vcops/user/conf/ssl/tcserver.keystore'
  impact 0.5
  ref 'DPMS Target VMware vRealize Operations Manager 6.x tcServer'
  tag check_id: 'C-88643r1_chk'
  tag severity: 'medium'
  tag gid: 'V-88951'
  tag rid: 'SV-99601r1_rule'
  tag stig_id: 'VROM-TC-000465'
  tag gtitle: 'SRG-APP-000176-WSR-000096'
  tag fix_id: 'F-95693r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000186']
  tag nist: ['IA-5 (2) (a) (1)']
end
