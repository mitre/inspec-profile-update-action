control 'SV-16798' do
  title 'VirtualCenter communications to the ESX Server are unencrypted.'
  desc 'User sessions with the ESX Server should be encrypted since transmitting data in plaintext may be viewed as it travels through the network. User sessions may be initiated from the VI client, Web Access, or through VirtualCenter. To encrypt session data, the sending component, such as a gateway or redirector, applies ciphers to alter the data before transmitting it. The receiving component uses a key to decrypt the data, returning it to its original form. To ensure the protection of the data transmitted to and from external network connections, ESX Server uses the 256-bit AES block encryption. ESX Server also uses 1024-bit RSA for key exchange. These encryption algorithms are the default for VI Client, VI Web Access, VirtualCenter sessions.'
  desc 'check', 'On the ESX Server service console perform the following:
# grep ssl /etc/vmware/hostd/config.xml 

(ssl)
(privatekey)/etc/vmware/ssl/DoD Key(/privatekey)
(certificate)/etc/vmware/ssl/DoD Cert(/certificate)
(/ssl)

If you do not see the DoD key and certificate listed between the SSL tags or the lines are commented out, this is a finding.'
  desc 'fix', 'Encrypt all VirtualCenter sessions with ESX Servers.'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-16214r1_chk'
  tag severity: 'medium'
  tag gid: 'V-15857'
  tag rid: 'SV-16798r1_rule'
  tag stig_id: 'ESX0580'
  tag gtitle: 'VirtualCenter to ESX Server comm. is not encyrpted'
  tag fix_id: 'F-15817r1_fix'
  tag 'documentable'
  tag responsibility: ['[Virtual Server Administrator]', 'Information Assurance Officer', 'System Administrator']
end
