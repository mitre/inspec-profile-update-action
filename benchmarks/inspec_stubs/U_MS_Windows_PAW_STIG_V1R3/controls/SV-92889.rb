control 'SV-92889' do
  title 'The Windows PAW must be configured so that all outbound connections to the Internet from a PAW are blocked.'
  desc 'Note: Internal domain connections from a PAW to communicate with IT resources being managed via the PAW with domain controllers or with a digital credential verification service (for example, Online Certificate Status Protocol [OCSP]) are allowed.

A main security architectural construct of a PAW is that the workstation is isolated from most Internet threats, including phishing, impersonation, and credential theft attacks. This isolation is partially implemented by blocking all outbound connections to the Internet.'
  desc 'check', 'Review the PAW configuration to verify all outbound connections to the Internet from the PAW are blocked except to communicate with IT resources being managed via the PAW, including the management console of authorized public cloud services; with domain controllers; or with a digital credential verification service (for example, OCSP).

Ask site personnel how outbound connections from the PAW to the Internet have been blocked. Two common methods are to either configure the host-based firewall to block all outbound connection requests to the Internet gateway or to configure the PAW with an Internet proxy address with a loopback address. Based on the method used at the site, review either the configuration of the host-based firewall or the PAW configuration and verify the configuration blocks all outbound Internet connections except to communicate with IT resources being managed via the PAW, with domain controllers, or with a digital credential verification service (for example, OCSP).

If the site has configured the PAW with a loopback address, verify a proxy server group policy has been set up with a loopback address (127.0.0.1) and assigned to the PAW Users group.

If the PAW system has not been configured to block all outbound connections to the Internet from a PAW except to communicate with IT resources being managed via the PAW, with domain controllers, or with a digital credential verification service, this is a finding.'
  desc 'fix', 'Configure the PAW host-based firewall to block outbound connection requests to the Internet gateway or configure the PAW with an Internet proxy address with a loopback address. Allowed exceptions include connections to communicate with IT resources being managed via the PAW, including the management console of authorized public cloud services; with domain controllers; or with a digital credential verification service (for example, OCSP).

If the PAW host-based firewall method is used, configure the firewall to block outbound connection requests to the Internet gateway. The exact configuration procedure will depend on which host-based firewall (for example, Host-Based Security System [HBSS]) is used on the PAW. DoD sites should refer to DoD policies and firewall STIGs to determine acceptable firewalls products.

If the Internet proxy address with a loopback address method is used, consider using the configuration instructions listed in of the Microsoft Privileged Access Workstation paper.

In addition, disable the capability of the administrator to manually override the proxy settings on each PAW.'
  impact 0.5
  ref 'DPMS Target Privileged Access Workstation (Windows)'
  tag check_id: 'C-77749r1_chk'
  tag severity: 'medium'
  tag gid: 'V-78183'
  tag rid: 'SV-92889r1_rule'
  tag stig_id: 'WPAW-00-002200'
  tag gtitle: 'PAW-00-002200'
  tag fix_id: 'F-84905r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002399']
  tag nist: ['SC-7 (9) (a)']
end
