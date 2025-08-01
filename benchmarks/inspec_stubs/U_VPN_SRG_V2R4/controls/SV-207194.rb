control 'SV-207194' do
  title 'If the site-to-site VPN implementation uses L2TP, L2TPv3 sessions must be authenticated prior to transporting traffic.'
  desc 'L2TPv3 sessions can be used to transport layer-2 protocols across an IP backbone. These protocols were intended for link-local scope only and are therefore less defended and not as well-known. As stated in DoD IPv6 IA Guidance for MO3 (S4-C7-1), the L2TP tunnels can also carry IP packets that are very difficult to filter because of the additional encapsulation. Hence, it is imperative that L2TP sessions are authenticated prior to transporting traffic.'
  desc 'check', 'If L2TP communications protocol is not used, this is not applicable.

Verify L2TPv3 sessions are configured to authenticate the traffic before transit. L2TPv3 sessions must be authenticated prior to transporting traffic.

If L2TPv3 sessions do not require authentication, this is a finding.'
  desc 'fix', 'If the site-to-site VPN implementation uses L2TPv3, configure L2TPv3 sessions to authenticate the traffic before transit.'
  impact 0.5
  ref 'DPMS Target Virtual Private Network (VPN)'
  tag check_id: 'C-7454r378203_chk'
  tag severity: 'medium'
  tag gid: 'V-207194'
  tag rid: 'SV-207194r608988_rule'
  tag stig_id: 'SRG-NET-000075-VPN-000260'
  tag gtitle: 'SRG-NET-000075'
  tag fix_id: 'F-7454r378204_fix'
  tag 'documentable'
  tag legacy: ['SV-106363', 'V-97225']
  tag cci: ['CCI-000068']
  tag nist: ['AC-17 (2)']
end
