control 'SV-214669' do
  title 'The Juniper SRX Services Gateway VPN must renegotiate the IPsec security association after 8 hours or less.'
  desc 'The IPsec SA and its corresponding key will expire either after the number of seconds or amount of traffic volume has exceeded the configured limit. A new SA is negotiated before the lifetime threshold of the existing SA is reached to ensure that a new SA is ready for use when the old one expires. The longer the lifetime of the IPsec SA, the longer the lifetime of the session key used to protect IP traffic. The SA is less secure with a longer lifetime because an attacker has a greater opportunity to collect traffic encrypted by the same key and subject it to cryptanalysis. However, a shorter lifetime causes IPsec peers to renegotiate Phase II more often resulting in the expenditure of additional resources.'
  desc 'check', 'Review all IPsec security associations configured globally or within IPsec profiles on the VPN gateway and examine the configured idle time. The default is 3600.

[edit]
show security ipsec proposal

View the value of the lifetime-seconds option.

If the IPsec proposal lifetime-seconds are not renegotiated after 8 hours or less of idle time, this is a finding.

If the IPsec proposal lifetime-seconds is not configured, this is a finding.'
  desc 'fix', 'Set the lifetime (in seconds) of the IPsec proposal to 8 hours or less. 

Example:

[edit]
set security ipsec proposal <P2-PROPOSAL-NAME> lifetime-seconds 28800'
  impact 0.5
  ref 'DPMS Target Juniper SRX Services Gateway VPN'
  tag check_id: 'C-15870r695321_chk'
  tag severity: 'medium'
  tag gid: 'V-214669'
  tag rid: 'SV-214669r695322_rule'
  tag stig_id: 'JUSX-VN-000002'
  tag gtitle: 'SRG-NET-000517'
  tag fix_id: 'F-15868r297595_fix'
  tag 'documentable'
  tag legacy: ['V-66631', 'SV-81121']
  tag cci: ['CCI-002361']
  tag nist: ['AC-12']
end
