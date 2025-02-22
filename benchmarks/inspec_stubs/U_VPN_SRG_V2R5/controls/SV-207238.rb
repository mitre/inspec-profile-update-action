control 'SV-207238' do
  title 'The VPN Gateway must renegotiate the security association after 24 hours or less or as defined by the organization.'
  desc 'When a VPN gateway creates an IPsec Security Association (SA), resources must be allocated to maintain the SA. These resources are wasted during periods of IPsec endpoint inactivity, which could result in the gateway’s inability to create new SAs for other endpoints, thereby preventing new sessions from connecting. The Internet Key Exchange (IKE) idle timeout may also be set to allow SAs associated with inactive endpoints to be deleted before the SA lifetime has expired, although this setting is not recommended at this time. The value of one hour or less is a common best practice.'
  desc 'check', 'Verify the VPN Gateway renegotiates the security association after 24 hours or less or as defined by the organization.

If the VPN Gateway does not renegotiate the security association after 24 hours or less or as defined by the organization, this is a finding.'
  desc 'fix', 'Configure the VPN Gateway to renegotiate the security association after 24 hours or less or as defined by the organization.'
  impact 0.5
  ref 'DPMS Target Virtual Private Network (VPN)'
  tag check_id: 'C-7498r378335_chk'
  tag severity: 'medium'
  tag gid: 'V-207238'
  tag rid: 'SV-207238r856710_rule'
  tag stig_id: 'SRG-NET-000337-VPN-001300'
  tag gtitle: 'SRG-NET-000337'
  tag fix_id: 'F-7498r378336_fix'
  tag 'documentable'
  tag legacy: ['SV-106293', 'V-97155']
  tag cci: ['CCI-002038']
  tag nist: ['IA-11']
end
