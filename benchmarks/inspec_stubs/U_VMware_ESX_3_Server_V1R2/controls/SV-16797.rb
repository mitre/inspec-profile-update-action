control 'SV-16797' do
  title 'VI Web Access sessions to the ESX Server are unencrypted.'
  desc 'User sessions with the ESX Server should be encrypted since transmitting data in plaintext may be viewed as it travels through the network. User sessions may be initiated from the VI client, Web Access, or through VirtualCenter. To encrypt session data, the sending component, such as a gateway or redirector, applies ciphers to alter the data before transmitting it. The receiving component uses a key to decrypt the data, returning it to its original form. To ensure the protection of the data transmitted to and from external network connections, ESX Server uses the 256-bit AES block encryption. ESX Server also uses 1024-bit RSA for key exchange. These encryption algorithms are the default for VI Client, VI Web Access, and VirtualCenter sessions.'
  desc 'check', '1. First verify Web Access is enabled by having the IAO/SA attempt to login to the ESX Server.  
2. Start the Web Browser
3. Enter the URL of the ESX Server: http://(host or server name)/ui.  The http should transition to https://(host or server name)/ui.  If it does not transition to https, this is a finding.'
  desc 'fix', 'Encrypt all Web Access session to ESX Servers.'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-16213r1_chk'
  tag severity: 'medium'
  tag gid: 'V-15856'
  tag rid: 'SV-16797r1_rule'
  tag stig_id: 'ESX0570'
  tag gtitle: 'VI Web Access sessions are not encrypted.'
  tag fix_id: 'F-15815r1_fix'
  tag 'documentable'
  tag responsibility: ['[Virtual Server Administrator]', 'Information Assurance Officer', 'System Administrator']
end
