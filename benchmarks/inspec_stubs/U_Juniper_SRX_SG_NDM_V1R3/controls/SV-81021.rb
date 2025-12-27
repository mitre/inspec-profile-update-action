control 'SV-81021' do
  title 'For nonlocal maintenance sessions using SSH, the Juniper SRX Services Gateway must securely configured SSHv2 with privacy options to protect the confidentiality of maintenance and diagnostic communications for nonlocal maintenance sessions.'
  desc 'To protect the confidentiality of nonlocal maintenance sessions when using SSH communications, SSHv2, AES ciphers, and key-exchange commands are configured. 

Nonlocal maintenance and diagnostic activities are those activities conducted by individuals communicating through a network, either an external network (e.g., the Internet) or an internal network. 

The SSHv2 protocol suite includes Layer 7 protocols such as SCP and SFTP which can be used for secure file transfers. The key-exchange commands limit the key exchanges to FIPS and DoD-approved methods.'
  desc 'check', 'Verify SSHv2, AES ciphers, and key-exchange commands are configured to protect confidentiality.

[edit]
show system services ssh

If SSHv2, AES ciphers, and key-exchange commands are not configured to protect confidentiality, this is a finding.'
  desc 'fix', 'Configure SSH confidentiality options to comply with DoD requirements.

[edit]
set system services ssh protocol-version v2
set system services ssh ciphers aes256-ctr
set system services ssh ciphers aes256-cbc
set system services ssh ciphers aes192-ctr
set system services ssh ciphers aes192-cbc
set system services ssh ciphers aes128-ctr
set system services ssh ciphers aes128-cbc
set system services ssh key-exchange dh-group14-sha1
set system services ssh key-exchange group-exchange-sha2
set system services ssh key-exchange ecdh-sha2-nistp256
set system services ssh key-exchange ecdh-sha2-nistp384
set system services ssh key-exchange ecdh-sha2-nistp521'
  impact 0.5
  ref 'DPMS Target Juniper SRX SG NDM'
  tag check_id: 'C-67177r1_chk'
  tag severity: 'medium'
  tag gid: 'V-66531'
  tag rid: 'SV-81021r1_rule'
  tag stig_id: 'JUSX-DM-000150'
  tag gtitle: 'SRG-APP-000412-NDM-000331'
  tag fix_id: 'F-72607r1_fix'
  tag 'documentable'
  tag cci: ['CCI-003123']
  tag nist: ['MA-4 (6)']
end
