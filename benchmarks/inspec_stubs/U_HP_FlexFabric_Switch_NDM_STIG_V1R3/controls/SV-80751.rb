control 'SV-80751' do
  title 'Applications used for nonlocal maintenance sessions must implement cryptographic mechanisms to protect the confidentiality of nonlocal maintenance and diagnostic communications.'
  desc 'This requires the use of secure protocols instead of their unsecured counterparts, such as SSH instead of telnet, SCP instead of FTP, and HTTPS instead of HTTP. If unsecured protocols (lacking cryptographic mechanisms) are used for sessions, the contents of those sessions will be susceptible to eavesdropping, potentially putting sensitive data (including administrator passwords) at risk of compromise and potentially allowing hijacking of maintenance sessions.'
  desc 'check', 'Determine if the HP FlexFabric Switch implements cryptographic mechanisms to protect the confidentiality of nonlocal maintenance and diagnostic communications. 

[HP] display ssh server status

 SSH server: Enable
 SSH version : 2.0
 SSH authentication-timeout : 60 second(s)
 SSH server key generating interval : 0 hour(s)
 SSH authentication retries : 3 time(s)
 SFTP server: Enable
 SFTP Server Idle-Timeout: 10 minute(s)
 Netconf server: Disable

[HP] display current | i sftp
 sftp server enable

If SSH and SFTP protocols are not configured for nonlocal device maintenance , this is a finding.'
  desc 'fix', 'Configure the HP FlexFabric Switch to implement cryptographic mechanisms to protect the confidentiality of nonlocal maintenance and diagnostic communications.

Generate local RSA key pairs on the SSH server: 

[HP] public-key local create rsa 
Enable the SSH server function:
[HP] ssh server enable

Enable the SFTP server function: 

[HP] sftp server enable

Configure the user interfaces for SSH clients: 

[HP] user-interface vty 0 63
[HP-ui-vty0-63] authentication-mode scheme

Configure a local device management user, assign password and enable service-type SSH: 

[HP] local-user admin
[HP-luser-admin] password simple xxxxxx
[HP-luser-admin] service-type ssh'
  impact 0.5
  ref 'DPMS Target HP Flex Fabric Switch 7 NDM'
  tag check_id: 'C-66907r1_chk'
  tag severity: 'medium'
  tag gid: 'V-66261'
  tag rid: 'SV-80751r1_rule'
  tag stig_id: 'HFFS-ND-000117'
  tag gtitle: 'SRG-APP-000412-NDM-000331'
  tag fix_id: 'F-72337r1_fix'
  tag 'documentable'
  tag cci: ['CCI-003123']
  tag nist: ['MA-4 (6)']
end
