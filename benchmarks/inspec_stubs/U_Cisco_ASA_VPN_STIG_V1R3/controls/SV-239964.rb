control 'SV-239964' do
  title 'The Cisco ASA VPN gateway must be configured to renegotiate the IKE security association after 24 hours or less.'
  desc 'When a VPN gateway creates an IPsec Security Association (SA), resources must be allocated to maintain the SA. These resources are wasted during periods of IPsec endpoint inactivity, which could result in the gateway’s inability to create new SAs for other endpoints, thereby preventing new sessions from connecting. The Internet Key Exchange (IKE) idle timeout may also be set to allow SAs associated with inactive endpoints to be deleted before the SA lifetime has expired, although this setting is not recommended at this time. The value of one hour or less is a common best practice.'
  desc 'check', 'Verify the VPN gateway renegotiates the IKE security association after 24 hours or less as shown in the example below.

crypto ikev2 policy 2
 encryption …
 …
 …
 …
 lifetime seconds 86400

If the VPN gateway does not renegotiate the IKE security association after 24 hours or less, this is a finding.'
  desc 'fix', 'Configure the VPN gateway to renegotiate the IKE security association after 24 hours or less as shown in the example below.

ASA2(config)# crypto ikev2 policy 2
ASA2(config-ikev2-policy)# lifetime seconds 86400
ASA2(config-ikev2-policy)# end'
  impact 0.5
  ref 'DPMS Target Cisco ASA VPN'
  tag check_id: 'C-43197r666296_chk'
  tag severity: 'medium'
  tag gid: 'V-239964'
  tag rid: 'SV-239964r856173_rule'
  tag stig_id: 'CASA-VN-000360'
  tag gtitle: 'SRG-NET-000337-VPN-001300'
  tag fix_id: 'F-43156r666297_fix'
  tag 'documentable'
  tag cci: ['CCI-002038']
  tag nist: ['IA-11']
end
