control 'SV-207123' do
  title 'The router must be configured to have all non-essential capabilities disabled.'
  desc 'A compromised router introduces risk to the entire network infrastructure, as well as data resources that are accessible via the network. The perimeter defense has no oversight or control of attacks by malicious users within the network. Preventing network breaches from within is dependent on implementing a comprehensive defense-in-depth strategy, including securing each device connected to the network. This is accomplished by following and implementing all security guidance applicable for each node type. A fundamental step in securing each router is to enable only the capabilities required for operation.'
  desc 'check', 'Review the router configuration to determine if services or functions not required for operation, or not related to router functionality (e.g., DNS, email client or server, FTP server, or web server) are enabled.

If unnecessary services and functions are enabled on the router, this is a finding.'
  desc 'fix', 'Remove unneeded services and functions from the router.

Removal is recommended because the service or function may be inadvertently enabled otherwise.

However, if removal is not possible, disable the service or function.'
  impact 0.3
  ref 'DPMS Target Router'
  tag check_id: 'C-7384r382262_chk'
  tag severity: 'low'
  tag gid: 'V-207123'
  tag rid: 'SV-207123r604135_rule'
  tag stig_id: 'SRG-NET-000131-RTR-000035'
  tag gtitle: 'SRG-NET-000131'
  tag fix_id: 'F-7384r382263_fix'
  tag 'documentable'
  tag legacy: ['V-55763', 'SV-70017']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
