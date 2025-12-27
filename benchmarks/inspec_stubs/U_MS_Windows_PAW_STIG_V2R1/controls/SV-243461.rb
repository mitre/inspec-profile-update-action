control 'SV-243461' do
  title 'The Windows PAW must be configured so that all outbound connections to the Internet from a PAW are blocked.'
  desc 'Note: Internal domain connections from a PAW to communicate with IT resources being managed via the PAW with domain controllers or with a digital credential verification service (for example, Online Certificate Status Protocol [OCSP]) are allowed.

A main security architectural construct of a PAW is that the workstation is isolated from most internet threats, including phishing, impersonation, and credential theft attacks. This isolation is partially implemented by blocking all outbound connections to the internet.'
  desc 'check', 'Review the PAW configuration to verify all outbound connections to the internet from the PAW are blocked except to communicate with IT resources being managed via the PAW, including the management console of authorized public cloud services, with domain controllers, or with a digital credential verification service (for example, OCSP).

Ask site personnel how outbound connections from the PAW to the internet have been blocked. Two common methods are to either configure the host-based firewall to block all outbound connection requests to the internet gateway or to configure the PAW with an internet proxy address with a loopback address. Based on the method used at the site, review either the configuration of the host-based firewall or the PAW configuration and verify the configuration blocks all outbound internet connections except to communicate with IT resources being managed via the PAW, with domain controllers, or with a digital credential verification service (for example, OCSP).

If the site has configured the PAW with a loopback address, verify a proxy server group policy has been set up with a loopback address (127.0.0.1) and assigned to the PAW Users group.

If the PAW system has not been configured to block all outbound connections to the internet from a PAW except to communicate with IT resources being managed via the PAW, with domain controllers, or with a digital credential verification service, this is a finding.'
  desc 'fix', 'Configure the PAW host-based firewall to block outbound connection requests to the internet gateway or configure the PAW with an internet proxy address with a loopback address. Allowed exceptions include connections to communicate with IT resources being managed via the PAW, including the management console of authorized public cloud services, with domain controllers, or with a digital credential verification service (for example, OCSP).

If the PAW host-based firewall method is used, configure the firewall to block outbound connection requests to the internet gateway. The exact configuration procedure will depend on which host-based firewall (for example, Endpoint Security Solution [ESS]) is used on the PAW. DoD sites should refer to DoD policies and firewall STIGs to determine acceptable firewalls products.

If the internet proxy address with a loopback address method is used, consider using the configuration instructions listed in the Microsoft Privileged Access Workstation paper.

In addition, disable the capability of the administrator to manually override the proxy settings on each PAW.'
  impact 0.5
  ref 'DPMS Target Windows PAW'
  tag check_id: 'C-46736r804957_chk'
  tag severity: 'medium'
  tag gid: 'V-243461'
  tag rid: 'SV-243461r804958_rule'
  tag stig_id: 'WPAW-00-002200'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-46693r804956_fix'
  tag 'documentable'
  tag legacy: ['V-78183', 'SV-92889']
  tag cci: ['CCI-000366', 'CCI-002399']
  tag nist: ['CM-6 b', 'SC-7 (9) (a)']
end
