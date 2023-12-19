control 'SV-239967' do
  title 'The Cisco ASA remote access VPN server must be configured to identify and authenticate users before granting access to the network.'
  desc "To assure accountability and prevent unauthenticated access, organizational users must be identified and authenticated to prevent potential misuse and compromise of the system.

Organizational users include organizational employees or individuals the organization deems to have equivalent status of employees (e.g., contractors). Organizational users (and any processes acting on behalf of users) must be uniquely identified and authenticated for all accesses except the following:

(i) Accesses explicitly identified and documented by the organization. Organizations document specific user actions that can be performed on the information system without identification or authentication; and

(ii) Accesses that occur through authorized use of group authenticators without individual authentication. Organizations may require unique identification of individuals' in-group accounts (e.g., shared privilege accounts) or for detailed accountability of individual activity.

This requirement only applies to components where this is specific to the function of the device or has the concept of an organizational user (e.g., VPN or proxy capability). This does not apply to authentication for the purpose of configuring the device itself (i.e., device management)."
  desc 'check', 'Verify the ASA is configured to uniquely identify and authenticate users before granting access to the network as shown in the example below.

tunnel-group ANY_CONNECT type remote-access
tunnel-group ANY_CONNECT webvpn-attributes
 authentication certificate

If the ASA is not configured to identify and authenticate users before granting access to the network, this is a finding.'
  desc 'fix', 'Configure the ASA to uniquely identify and authenticate users before granting access to the network. 

ASA1(config)# tunnel-group ANY_CONNECT webvpn-attributes
ASA1(config-tunnel-webvpn)# authentication certificate 
ASA1(config-tunnel-webvpn)# end'
  impact 0.5
  ref 'DPMS Target Cisco ASA VPN'
  tag check_id: 'C-43200r666305_chk'
  tag severity: 'medium'
  tag gid: 'V-239967'
  tag rid: 'SV-239967r666307_rule'
  tag stig_id: 'CASA-VN-000410'
  tag gtitle: 'SRG-NET-000138-VPN-000490'
  tag fix_id: 'F-43159r666306_fix'
  tag 'documentable'
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end
