control 'SV-214670' do
  title 'The Juniper SRX Services Gateway VPN must renegotiate the IKE security association after 24 hours or less.'
  desc 'When a VPN gateway creates an IPsec Security Association (SA), resources must be allocated to maintain the SA. These resources are wasted during periods of IPsec endpoint inactivity, which could result in the gateway’s inability to create new SAs for other endpoints, thereby preventing new sessions from connecting. The Internet Key Exchange (IKE) idle timeout may also be set to allow SAs associated with inactive endpoints to be deleted before the SA lifetime has expired, although this setting is not recommended at this time. The value of one hour or less is a common best practice.'
  desc 'check', 'Review all IPsec security associations configured globally or within IPsec profiles on the VPN gateway and examine the configured idle time. The idle time value must be one hour or less. If idle time is not configured, determine the default used by the gateway. The default value is 28800 seconds which is compliant.

[edit]
show security ike proposal

View the value of the lifetime-seconds option.

If the IKE security associations are not renegotiated after 24 hours or less of idle time, this is a finding.'
  desc 'fix', 'Specify the lifetime (in seconds) of an IKE security association (SA). When the SA expires, it is replaced by a new SA, the security parameter index (SPI), or terminated if the peer cannot be contacted for renegotiation.

Example:

[edit]
set security ike proposal <P1-PROPOSAL-NAME> lifetime-seconds 86400'
  impact 0.5
  ref 'DPMS Target Juniper SRX Services Gateway VPN'
  tag check_id: 'C-15871r856573_chk'
  tag severity: 'medium'
  tag gid: 'V-214670'
  tag rid: 'SV-214670r856574_rule'
  tag stig_id: 'JUSX-VN-000003'
  tag gtitle: 'SRG-NET-000517'
  tag fix_id: 'F-15869r297598_fix'
  tag 'documentable'
  tag legacy: ['V-66643', 'SV-81133']
  tag cci: ['CCI-002361']
  tag nist: ['AC-12']
end
