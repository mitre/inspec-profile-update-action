control 'SV-256741' do
  title 'The Envoy private key file must be protected from unauthorized access.'
  desc "Envoy's private key is used to prove the identity of the server to clients and securely exchange the shared secret key used to encrypt communications between the web server and clients. 
 
By gaining access to the private key, an attacker can pretend to be an authorized server and decrypt the Transport Layer Security (TLS) traffic between a client and the web server."
  desc 'check', 'At  the command prompt, run the following command: 
 
# stat -c "%n permissions are %a, is owned by %U and group owned by %G" /etc/vmware-rhttpproxy/ssl/rui.key 
 
Expected result: 
 
/etc/vmware-rhttpproxy/ssl/rui.key permissions are 600, is owned by root and group owned by root 
 
If the output does not match the expected result, this is a finding.'
  desc 'fix', 'At the command prompt, run the following commands: 
 
# chmod 600 /etc/vmware-rhttpproxy/ssl/rui.key 
# chown root:root /etc/vmware-rhttpproxy/ssl/rui.key'
  impact 0.5
  ref 'DPMS Target VMware vSphere 7.0 vCA RhttpProxy'
  tag check_id: 'C-60416r889159_chk'
  tag severity: 'medium'
  tag gid: 'V-256741'
  tag rid: 'SV-256741r889161_rule'
  tag stig_id: 'VCRP-70-000005'
  tag gtitle: 'SRG-APP-000176-WSR-000096'
  tag fix_id: 'F-60359r889160_fix'
  tag 'documentable'
  tag cci: ['CCI-000186']
  tag nist: ['IA-5 (2) (a) (1)']
end
