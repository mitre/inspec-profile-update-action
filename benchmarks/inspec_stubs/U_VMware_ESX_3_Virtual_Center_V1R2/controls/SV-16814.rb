control 'SV-16814' do
  title 'VI Web Access sessions with VirtualCenter are unencrypted.'
  desc 'User sessions with VirtualCenter should be encrypted since transmitting data in plaintext may be viewed as it travels through the network. User sessions may be initiated from the VI client and VI Web Access. To encrypt session data, the sending component, such as a gateway or redirector, applies ciphers to alter the data before transmitting it. The receiving component uses a key to decrypt the data, returning it to its original form. To ensure the protection of the data transmitted to and from external network connections, all VI client and web access sessions with VirtualCenter will be encrypted with a FIPS 140-2 encryption algorithm.'
  desc 'check', '1. Login to VirtualCenter through the VI Client.
2. Select an ESX Server host from the inventory panel.
3. Select the configuration tab.
4. Select advanced settings in the software section.
5. Verify the “Config.Defaults.security.host.ruissl” is checked.  This requires SSL to be used when communicating with the host over 902.  If this is not checked, this is a finding.'
  desc 'fix', 'Encrypt all VI Web Access sessions with VirtualCenter.'
  impact 0.5
  ref 'DPMS Target VMware VirtualCenter'
  tag check_id: 'C-16230r1_chk'
  tag severity: 'medium'
  tag gid: 'V-15873'
  tag rid: 'SV-16814r1_rule'
  tag stig_id: 'ESX0740'
  tag gtitle: 'VI Web Access sessions are unencrypted'
  tag fix_id: 'F-15833r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer', '[Virtual Server Administrator]']
  tag ia_controls: 'ECCT-1, ECCT-2'
end
