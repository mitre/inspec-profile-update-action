control 'SV-206690' do
  title 'The firewall must disable or remove unnecessary network services and functions that are not used as part of its role in the architecture.'
  desc 'Network devices are capable of providing a wide variety of functions (capabilities or processes) and services. Some of these functions and services are installed and enabled by default. The organization must determine which functions and services are required to perform the content filtering and other necessary core functionality for each component of the firewall. These unnecessary capabilities or services are often overlooked and therefore may remain unsecured. They increase the risk to the platform by providing additional attack vectors.

Some services may be security related but, based on the firewall’s role in the architecture, must not be installed on the same hardware. For example, the device may serve as a router, VPN, or other perimeter services. However, if these functions are not part of the documented role of the firewall in the enterprise or branch architecture, the software and licenses should not be installed on the device. This mitigates the risk of exploitation of unconfigured services or services that are not kept updated with security fixes. If left unsecured, these services may provide a threat vector.

Some services are not authorized for combination with the firewall and individual policy must be in place to instruct the administrator to remove these services. Examples of these services are Network Time Protocol (NTP), domain name server (DNS), email server, FTP server, web server, and Dynamic Host Configuration Protocol (DHCP). 

Only remove unauthorized services. This control is not intended to restrict the use of firewalls with multiple authorized roles.'
  desc 'check', 'Review the documentation and architecture for the device or check the system-installed licenses or services.

Determine what services and functions are installed on the firewall. Compare installed services and functions to the documentation showing the approved services.

If unneeded services and functions are installed on the device but are not part of the documented role of the device, this is a finding.'
  desc 'fix', 'Display and remove unnecessary licenses, services, and functions from the firewall. Examples include NTP, DNS, and DHCP.

Note: Only remove unauthorized services. This control is not intended to restrict the use of network devices with multiple authorized roles.'
  impact 0.5
  ref 'DPMS Target Firewall'
  tag check_id: 'C-6947r297849_chk'
  tag severity: 'medium'
  tag gid: 'V-206690'
  tag rid: 'SV-206690r604133_rule'
  tag stig_id: 'SRG-NET-000131-FW-000025'
  tag gtitle: 'SRG-NET-000131'
  tag fix_id: 'F-6947r297850_fix'
  tag 'documentable'
  tag legacy: ['SV-94167', 'V-79461']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
