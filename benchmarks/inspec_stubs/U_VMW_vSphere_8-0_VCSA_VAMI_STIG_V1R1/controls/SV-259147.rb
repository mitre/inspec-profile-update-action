control 'SV-259147' do
  title "The vCenter VAMI service must restrict access to the web server's private key."
  desc "The web server's private key is used to prove the identity of the server to clients and securely exchange the shared secret key used to encrypt communications between the web server and clients. By gaining access to the private key, an attacker can pretend to be an authorized server and decrypt the Secure Sockets Layer (SSL) traffic between a client and the web server."
  desc 'check', 'At the command prompt, run the following command:

# stat -c "%n has %a permissions and is owned by %U:%G" /etc/applmgmt/appliance/server.pem

Expected result:

/etc/applmgmt/appliance/server.pem has 600 permissions and is owned by root:root

If the output does not match the expected result, this is a finding.'
  desc 'fix', 'At the command prompt, run the following commands:

# chown root:root /etc/applmgmt/appliance/server.pem
# chmod 600 /etc/applmgmt/appliance/server.pem'
  impact 0.5
  ref 'DPMS Target VMware vSphere 8.0 VCSA VAMI'
  tag check_id: 'C-62887r935343_chk'
  tag severity: 'medium'
  tag gid: 'V-259147'
  tag rid: 'SV-259147r935345_rule'
  tag stig_id: 'VCLD-80-000040'
  tag gtitle: 'SRG-APP-000176-WSR-000096'
  tag fix_id: 'F-62796r935344_fix'
  tag 'documentable'
  tag cci: ['CCI-000186']
  tag nist: ['IA-5 (2) (a) (1)']
end
