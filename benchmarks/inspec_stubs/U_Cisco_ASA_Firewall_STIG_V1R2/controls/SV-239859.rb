control 'SV-239859' do
  title 'The Cisco ASA must be configured to disable or remove unnecessary network services and functions that are not used as part of its role in the architecture.'
  desc 'Network devices are capable of providing a wide variety of functions (capabilities or processes) and services. Some of these functions and services are installed and enabled by default. The organization must determine which functions and services are required to perform the content filtering and other necessary core functionality for each component of the firewall. These unnecessary capabilities or services are often overlooked and therefore may remain unsecured. They increase the risk to the platform by providing additional attack vectors.

Some services may be security related but, based on the firewall’s role in the architecture, must not be installed on the same hardware. For example, the device may serve as a router, VPN, or other perimeter services. However, if these functions are not part of the documented role of the firewall in the enterprise or branch architecture, the software and licenses should not be installed on the device. This mitigates the risk of exploitation of unconfigured services or services that are not kept updated with security fixes. If left unsecured, these services may provide a threat vector.

Some services are not authorized for combination with the firewall and individual policy must be in place to instruct the administrator to remove these services. Examples of these services are Network Time Protocol (NTP), domain name server (DNS), email server, FTP server, web server, and Dynamic Host Configuration Protocol (DHCP). 

Only remove unauthorized services. This control is not intended to restrict the use of firewalls with multiple authorized roles.'
  desc 'check', 'Features such as telnet should never be enabled, while other features should only be enabled if required for operations. In the example below, http and telnet service is enabled.

http server enable
…
…
…
telnet 10.1.22.2 255.255.255.255 INSIDE

Note: The command http server actually enables https and is required for ASDM.

If any unnecessary or non-secure ports, protocols, or services are enabled, this is a finding.'
  desc 'fix', 'Disable features that should not be enabled unless required for operations.

ASA(config)# no http server enable
ASA(config)# no telnet 10.1.22.2 255.255.255.255 INSIDE
ASA(config)# end

Note: Telnet must always be disabled.'
  impact 0.5
  ref 'DPMS Target Cisco ASA Firewall'
  tag check_id: 'C-43092r665861_chk'
  tag severity: 'medium'
  tag gid: 'V-239859'
  tag rid: 'SV-239859r665863_rule'
  tag stig_id: 'CASA-FW-000130'
  tag gtitle: 'SRG-NET-000131-FW-000025'
  tag fix_id: 'F-43051r665862_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
