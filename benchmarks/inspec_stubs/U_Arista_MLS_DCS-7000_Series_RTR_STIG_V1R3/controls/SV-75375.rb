control 'SV-75375' do
  title 'The Arista Multilayer Switch must be configured to disable non-essential capabilities.'
  desc 'A compromised router introduces risk to the entire network infrastructure as well as data resources that are accessible via the network. The perimeter defense has no oversight or control of attacks by malicious users within the network. Preventing network breaches from within is dependent on implementing a comprehensive defense-in-depth strategy, including securing each device connected to the network. This is accomplished by following and implementing all security guidance applicable for each node type. A fundamental step in securing each router is to enable only the capabilities required for operation.'
  desc 'check', 'Review the router configuration to determine if services or functions not required for operation, or not related to router functionality (e.g., DNS, email client or server, FTP server, or web server) are enabled.

If unnecessary services and functions are enabled on the router, this is a finding.'
  desc 'fix', 'Remove unneeded services and functions from the router. Removal is recommended since the service or function may be inadvertently enabled otherwise. However, if removal is not possible, disable the service or function.'
  impact 0.5
  ref 'DPMS Target Arista DCS-7000 series RTR'
  tag check_id: 'C-61863r1_chk'
  tag severity: 'medium'
  tag gid: 'V-60917'
  tag rid: 'SV-75375r1_rule'
  tag stig_id: 'AMLS-L3-000240'
  tag gtitle: 'SRG-NET-000131-RTR-000035'
  tag fix_id: 'F-66629r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
