control 'SV-92887' do
  title 'The Windows PAW must be configured so that all inbound ports and services to a PAW are blocked except as needed for monitoring, scanning, and management tools or when the inbound communication is a response to an outbound connection request.'
  desc 'A main security architectural construct of a PAW is that the workstation is isolated from most Internet threats, including phishing, impersonation, and credential theft attacks. This isolation is partially implemented by blocking unsolicited inbound traffic to the PAW.'
  desc 'check', 'Obtain a list of all ports and services required for site monitoring, scanning, and management tools.

Review the configuration setting of the PAW host-based firewall.

Verify the firewall is configured to block all inbound ports and services from a PAW except as needed for monitoring, scanning, and management tools or when the inbound communication is a response to an outbound connection request.

Note: The exact procedure for verifying the configuration will depend on which host-based firewall (for example, Host-Based Security System, or HBSS) is used on the PAW.  DoD sites should refer to DoD policies and firewall STIGs to determine acceptable firewalls products.

If the PAW host-based firewall is not configured to block all inbound ports and services from a PAW except as needed for monitoring, scanning, and management tools or when the inbound communication is a response to an outbound connection request, this is a finding.'
  desc 'fix', "Determine which inbound ports, services, addresses, or subnets are needed on the PAW for the organization's monitoring, scanning, and management tools.

Configure the host-based firewall on the PAW to block all inbound connection requests except for organizational monitoring, scanning, and management tools or for inbound connections that are responses to outbound connection requests.

Configure the host-based firewall on the PAW to block users with local administrative access from creating or modifying local firewall rules.

Note: The exact configuration procedure will depend on which host-based firewall (for example, Host-Based Security System [HBSS]) is used on the PAW. DoD sites should refer to DoD policies and firewall STIGs to determine acceptable firewalls products."
  impact 0.5
  ref 'DPMS Target Privileged Access Workstation (Windows)'
  tag check_id: 'C-77747r1_chk'
  tag severity: 'medium'
  tag gid: 'V-78181'
  tag rid: 'SV-92887r1_rule'
  tag stig_id: 'WPAW-00-002100'
  tag gtitle: 'PAW-00-002100'
  tag fix_id: 'F-84903r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002403']
  tag nist: ['SC-7 (11)']
end
