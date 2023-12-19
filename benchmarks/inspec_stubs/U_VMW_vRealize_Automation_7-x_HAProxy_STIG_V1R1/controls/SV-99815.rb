control 'SV-99815' do
  title 'HAProxys private key must have access restricted.'
  desc "HAProxy's private key is used to prove the identity of the server to clients and securely exchange the shared secret key used to encrypt communications between the web server and clients.

Only authenticated system administrators or the designated PKI Sponsor for the web server must have access to the web server's private key. 

By gaining access to the private key, an attacker can pretend to be an authorized server and decrypt the encrypted traffic between a client and the web server."
  desc 'check', 'At the command prompt, execute the following command:

ls -al /etc/apache2/server.pem

If the permissions on the file are not "600", this is a finding.'
  desc 'fix', 'At the command prompt, execute the following command:s:

chmod 600 /etc/apache2/server.pem'
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7.x HAProxy'
  tag check_id: 'C-88857r1_chk'
  tag severity: 'medium'
  tag gid: 'V-89165'
  tag rid: 'SV-99815r1_rule'
  tag stig_id: 'VRAU-HA-000200'
  tag gtitle: 'SRG-APP-000176-WSR-000096'
  tag fix_id: 'F-95907r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000186']
  tag nist: ['IA-5 (2) (a) (1)']
end
