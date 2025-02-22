control 'SV-234144' do
  title 'The FortiGate firewall must disable or remove unnecessary network services and functions that are not used as part of its role in the architecture.'
  desc 'Network devices are capable of providing a wide variety of functions (capabilities or processes) and services. Some of these functions and services are installed and enabled by default. The organization must determine which functions and services are required to perform the content filtering and other necessary core functionality for each component of the firewall. These unnecessary capabilities or services are often overlooked and therefore may remain unsecured. They increase the risk to the platform by providing additional attack vectors.

Some services may be security related, but based on the firewall’s role in the architecture, must not be installed on the same hardware. For example, the device may serve as a router, VPN, or other perimeter services. However, if these functions are not part of the documented role of the firewall in the enterprise or branch architecture, the software and licenses must not be installed on the device. This mitigates the risk of exploitation of unconfigured services or services that are not kept updated with security fixes. If left unsecured, these services may provide a threat vector.

Some services are not authorized for combination with the firewall and individual policy must be in place to instruct the administrator to remove these services. Examples of these services are Network Time Protocol (NTP), domain name server (DNS), email server, FTP server, web server, and Dynamic Host Configuration Protocol (DHCP). 

Only remove unauthorized services. This control is not intended to restrict the use of firewalls with multiple authorized roles.'
  desc 'check', 'Log in to the FortiGate GUI with Super-Admin privilege.

1. Open a CLI console, via SSH or available from the GUI.
2. Run the following command:
     # show full-configuration system interface
3. Review configuration for unnecessary services.

If unnecessary services are configured, this is a finding.'
  desc 'fix', 'Log in to the FortiGate GUI with Super-Admin privilege.

1. Open a CLI console, via SSH or available from the GUI.
2. Run the following command:
     # config system interface
     #    edit {interface-name}
     #    get | grep enable
     #    get | grep allowaccess
Disable each service in {} that needs to be removed using:
     # config system interface
     #    edit {interface-name}
     #    set {service} disable
     # end'
  impact 0.5
  ref 'DPMS Target Fortinet FortiGate Firewall'
  tag check_id: 'C-37329r611430_chk'
  tag severity: 'medium'
  tag gid: 'V-234144'
  tag rid: 'SV-234144r611432_rule'
  tag stig_id: 'FNFG-FW-000065'
  tag gtitle: 'SRG-NET-000131-FW-000025'
  tag fix_id: 'F-37294r611431_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
