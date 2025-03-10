control 'SV-240805' do
  title 'tc Server ALL must only allow authenticated system administrators to have access to the keystore.'
  desc "The web server's private key is used to prove the identity of the server to clients and securely exchange the shared secret key used to encrypt communications between the web server and clients.

By gaining access to the private key, an attacker can pretend to be an authorized server and decrypt the SSL traffic between a client and the web server.

tc Server stores the server's private key in a keystore file. The vRA keystore file is tcserver.keystore, and this file must be protected to only allow system administrators and other authorized users to have access to it."
  desc 'check', 'At the command prompt, execute the following command:

ls -al /opt/vmware/horizon/workspace/conf/tcserver.keystore

Verify that file permissions are set to "640" or more restrictive. Verify that the owner is horizon and group-owner is www.

If either of these conditions are not met, this is a finding.'
  desc 'fix', 'At the command prompt, execute the following commands:

chown horizon:www /opt/vmware/horizon/workspace/conf/tcserver.keystore

chmod 640 /opt/vmware/horizon/workspace/conf/tcserver.keystore'
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7-x tc Server'
  tag check_id: 'C-44038r674471_chk'
  tag severity: 'medium'
  tag gid: 'V-240805'
  tag rid: 'SV-240805r674472_rule'
  tag stig_id: 'VRAU-TC-000450'
  tag gtitle: 'SRG-APP-000176-WSR-000096'
  tag fix_id: 'F-43997r674158_fix'
  tag 'documentable'
  tag legacy: ['SV-100997', 'V-90347']
  tag cci: ['CCI-000186']
  tag nist: ['IA-5 (2) (a) (1)']
end
