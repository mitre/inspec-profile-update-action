control 'SV-77315' do
  title 'The Riverbed Optimization System (RiOS) must not have unrelated or unnecessary services enabled on the host.'
  desc 'Because Wan Optimization is optimally installed in the architecture at the perimeter, installation of unnecessary functions and services on the same host increases the risk by implementing these functions before the network inspection functions and excessive open ports on the firewall for these functions and services to operation. Loading functions that are outside the scope and unrelated to the WAN optimization function is unauthorized and may create an attack vector. Related services include content filtering, traffic analysis, decryption, caching, and traffic inspection tools (e.g., firewall, IDS), unrelated services include email, DNS, web server.

When the solution is implemented using a Steelhead CX hardware appliance implementation consisting of the RiOS installed on the SteelHead, administrators are not able to install any software that is not part of a Riverbed upgrade. RiOS enforces this by performing a validity check when an upgrade is attempted.

However, the RiOS application suite is available in a virtual appliance version which can be installed on an organization-provided host. This type of implementation adds risk because more ports may need to be opened in the firewall if placed in the recommended logical position in the architecture after the router and before the firewall and IDS. The traffic should then be routed for inspection after traversing the wan optimizer.'
  desc 'check', 'If RiOS is installed on the SteelHead appliance, this is a finding.

Inspect the services and applications that are installed on the host with the RiOS application suite.
Ask the site representative if a security review using the applicable STIG has been performed on the operating system and applications that are co-hosted. 

If unrelated or unnecessary services are installed on the same host as the RiOS, this is a finding.

If a security review using the applicable STIG has not been performed on the operating system and applications co-hosted on with the RiOS, this is a finding.'
  desc 'fix', 'Disable or uninstall unrelated or unnecessary services from the host.'
  impact 0.5
  ref 'DPMS Target Riverbed SteelHead CX Version 8 ALG'
  tag check_id: 'C-63619r1_chk'
  tag severity: 'medium'
  tag gid: 'V-62825'
  tag rid: 'SV-77315r1_rule'
  tag stig_id: 'RICX-AG-000086'
  tag gtitle: 'SRG-NET-000131-ALG-000085'
  tag fix_id: 'F-68743r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
