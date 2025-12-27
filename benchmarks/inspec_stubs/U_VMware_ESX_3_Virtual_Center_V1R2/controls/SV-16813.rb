control 'SV-16813' do
  title 'VI Client sessions with VirtualCenter are unencrypted.'
  desc 'User sessions with VirtualCenter should be encrypted since transmitting data in plaintext may be viewed as it travels through the network. User sessions may be initiated from the VI client and VI Web Access. To encrypt session data, the sending component, such as a gateway or redirector, applies ciphers to alter the data before transmitting it. The receiving component uses a key to decrypt the data, returning it to its original form. To ensure the protection of the data transmitted to and from external network connections, all VI client and web access sessions with VirtualCenter will be encrypted with a FIPS 140-2 encryption algorithm.'
  desc 'check', '1. On the VirtualCenter Server go to Start> Program Files>VMware>Infrastructure>Virtual Infrastructure Client>Launcher.
2. Open the VpxClient.exe.config file with Notepad.
3. Verify https:443 is configured.  
(appSettings)
(add key = “protocolports” value = “https:443”/)
(/appSettings)

If this setting is not set, this is a finding.'
  desc 'fix', 'Encrypt all VI Client sessions to the VirtualCenter Server.'
  impact 0.5
  ref 'DPMS Target VMware VirtualCenter'
  tag check_id: 'C-16229r1_chk'
  tag severity: 'medium'
  tag gid: 'V-15872'
  tag rid: 'SV-16813r1_rule'
  tag stig_id: 'ESX0730'
  tag gtitle: 'VI Client sessions are unencrypted'
  tag fix_id: 'F-15832r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer', '[Virtual Server Administrator]']
end
