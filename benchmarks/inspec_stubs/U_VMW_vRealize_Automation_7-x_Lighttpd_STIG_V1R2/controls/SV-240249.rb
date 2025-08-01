control 'SV-240249' do
  title 'Lighttpd must have private key access restricted.'
  desc "Lighttpd's private key is used to prove the identity of the server to clients and securely exchange the shared secret key used to encrypt communications between the web server and clients.

Only authenticated system administrators or the designated PKI Sponsor for the web server must have access to the web servers private key. 

By gaining access to the private key, an attacker can pretend to be an authorized server and decrypt the encrypted traffic between a client and the web server."
  desc 'check', 'At the command prompt, execute the following command:

ls -al /opt/vmware/etc/lighttpd/server.pem

If the "server.pem" file is not owned by "root" or the file permissions are not "400", this is a finding.'
  desc 'fix', 'At the command prompt, execute the following commands:

chown root:root /opt/vmware/etc/lighttpd/server.pem
chmod 400 /opt/vmware/etc/lighttpd/server.pem'
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7-x Lighttpd'
  tag check_id: 'C-43482r667922_chk'
  tag severity: 'medium'
  tag gid: 'V-240249'
  tag rid: 'SV-240249r879613_rule'
  tag stig_id: 'VRAU-LI-000235'
  tag gtitle: 'SRG-APP-000176-WSR-000096'
  tag fix_id: 'F-43441r667923_fix'
  tag 'documentable'
  tag legacy: ['SV-99929', 'V-89279']
  tag cci: ['CCI-000186']
  tag nist: ['IA-5 (2) (a) (1)']
end
