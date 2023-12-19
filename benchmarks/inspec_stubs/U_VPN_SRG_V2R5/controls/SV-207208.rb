control 'SV-207208' do
  title 'The VPN Gateway must uniquely identify and authenticate organizational users (or processes acting on behalf of organizational users).'
  desc "To assure accountability and prevent unauthenticated access, organizational users must be identified and authenticated to prevent potential misuse and compromise of the system.

Organizational users include organizational employees or individuals the organization deems to have equivalent status of employees (e.g., contractors). Organizational users (and any processes acting on behalf of users) must be uniquely identified and authenticated for all accesses except the following.

(i) Accesses explicitly identified and documented by the organization. Organizations document specific user actions that can be performed on the information system without identification or authentication; and

(ii) Accesses that occur through authorized use of group authenticators without individual authentication. Organizations may require unique identification of individuals' in-group accounts (e.g., shared privilege accounts) or for detailed accountability of individual activity.

This requirement only applies to components where this is specific to the function of the device or has the concept of an organizational user (e.g., VPN or proxy capability). This does not apply to authentication for the purpose of configuring the device itself (i.e., device management)."
  desc 'check', 'Verify the VPN Gateway is configured to uniquely identify and authenticate organizational users (or processes acting on behalf of organizational users).

If the VPN Gateway does not uniquely identify and authenticate organizational users (or processes acting on behalf of organizational users), this is a finding.'
  desc 'fix', 'Configure the VPN Gateway to uniquely identify and authenticate organizational users (or processes acting on behalf of organizational users).'
  impact 0.5
  ref 'DPMS Target Virtual Private Network (VPN)'
  tag check_id: 'C-7468r378245_chk'
  tag severity: 'medium'
  tag gid: 'V-207208'
  tag rid: 'SV-207208r608988_rule'
  tag stig_id: 'SRG-NET-000138-VPN-000490'
  tag gtitle: 'SRG-NET-000138'
  tag fix_id: 'F-7468r378246_fix'
  tag 'documentable'
  tag legacy: ['V-97087', 'SV-106225']
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end
