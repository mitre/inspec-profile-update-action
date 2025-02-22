control 'SV-81133' do
  title 'The Juniper SRX Services Gateway VPN must renegotiate the security association after 24 hours or less.'
  desc 'When a VPN gateway creates an IPsec Security Association (SA), resources must be allocated to maintain the SA. These resources are wasted during periods of IPsec endpoint inactivity, which could result in the gateway’s inability to create new SAs for other endpoints, thereby preventing new sessions from connecting. The Internet Key Exchange (IKE) idle timeout may also be set to allow SAs associated with inactive endpoints to be deleted before the SA lifetime has expired, although this setting is not recommended at this time. The value of one hour or less is a common best practice.'
  desc 'check', 'Review all IPsec security associations configured globally or within IPsec profiles on the VPN gateway and examine the configured idle time. The idle time value must be one hour or less. If idle time is not configured, determine the default used by the gateway. The default value is 28800 seconds.

[edit]
show security ike proposal

View the value of the lifetime-seconds option.

If the IKE security associations are not renegotiated after 24 hours or less of idle time, this is a finding.

If the IKE proposal lifetime-seconds is not configured, this is not a finding.'
  desc 'fix', 'Specify the lifetime (in seconds) of an IKE security association (SA). When the SA expires, it is replaced by a new SA, the security parameter index (SPI), or terminated if the peer cannot be contacted for renegotiation.

Example:

[edit]
set security ike proposal <P1-PROPOSAL-NAME> lifetime-seconds 86400'
  impact 0.5
  ref 'DPMS Target Juniper SRX SG VPN'
  tag check_id: 'C-67269r1_chk'
  tag severity: 'medium'
  tag gid: 'V-66643'
  tag rid: 'SV-81133r1_rule'
  tag stig_id: 'JUSX-VN-000003'
  tag gtitle: 'SRG-NET-000517'
  tag fix_id: 'F-72719r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002361']
  tag nist: ['AC-12']
end
