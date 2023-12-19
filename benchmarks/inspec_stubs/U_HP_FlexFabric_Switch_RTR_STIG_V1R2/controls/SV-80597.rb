control 'SV-80597' do
  title 'The HP FlexFabric Switch must be configured to disable non-essential capabilities.'
  desc 'A compromised router introduces risk to the entire network infrastructure as well as data resources that are accessible via the network. The perimeter defense has no oversight or control of attacks by malicious users within the network. Preventing network breaches from within is dependent on implementing a comprehensive defense-in-depth strategy including securing each device connected to the network. This is accomplished by following and implementing all security guidance applicable for each node type. A fundamental step in securing each router is to enable only the capabilities required for operation.'
  desc 'check', 'Review the configuration to verify that non-essential services are not enabled, if these services are enabled, this is a finding:

[HP] display ftp-server
FTP is not configured.

[HP] display current-configuration | include telnet

Note: When Telnet server is enabled, the output for this command is telnet server enable.'
  desc 'fix', 'Disable unsecure protocols and services on the HP FlexFabric Switch:

[HP] undo ftp server enable
[HP] undo telnet server enable

Note: By default, both FTP and Telnet services are disabled.'
  impact 0.5
  ref 'DPMS Target HP Flex Fabric Switch 7 RTR'
  tag check_id: 'C-66753r1_chk'
  tag severity: 'medium'
  tag gid: 'V-66107'
  tag rid: 'SV-80597r1_rule'
  tag stig_id: 'HFFS-RT-000006'
  tag gtitle: 'SRG-NET-000131-RTR-000035'
  tag fix_id: 'F-72183r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
