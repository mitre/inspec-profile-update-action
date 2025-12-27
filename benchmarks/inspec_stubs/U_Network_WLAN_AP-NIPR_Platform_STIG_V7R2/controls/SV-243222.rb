control 'SV-243222' do
  title 'WLAN EAP-TLS implementation must use certificate-based PKI authentication to connect to DoD networks.'
  desc 'DoD certificate-based PKI authentication is strong, two-factor authentication that relies on carefully evaluated cryptographic modules. Implementations of EAP-TLS that are not integrated with certificate-based PKI could have security vulnerabilities. 

For example, an implementation that uses a client certificate on laptop without a second factor could enable an adversary with access to the laptop to connect to the WLAN without a PIN or password. Systems that do not use the certificate-based PKI are also much more likely to be vulnerable to weaknesses in the underlying public key infrastructure (PKI) that supports EAP-TLS.

Certificate-based PKI authentication must be used to connect WLAN client devices to DoD networks. The certificate-based PKI authentication should directly support the WLAN EAP-TLS implementation. 

At least one layer of user authentication must enforce network authentication requirements (e.g., CAC authentication) before the user is able to access DoD information resources.'
  desc 'check', "Interview the site ISSO and SA. Determine if the site's network is configured to require certificate-based PKI authentication before a WLAN user is connected to the network. 

If certificate-based PKI authentication is not required prior to a DoD WLAN user accessing the DoD network, this is a finding.

Note: This check does not apply to medical devices. Medical devices are permitted to connect to the WLAN using pre-shared keys."
  desc 'fix', 'Integrate certificate-based PKI authentication into the WLAN authentication process.'
  impact 0.5
  ref 'DPMS Target Network WLAN AP-NIPR Platform'
  tag check_id: 'C-46497r720119_chk'
  tag severity: 'medium'
  tag gid: 'V-243222'
  tag rid: 'SV-243222r720121_rule'
  tag stig_id: 'WLAN-NW-000700'
  tag gtitle: 'SRG-NET-000070'
  tag fix_id: 'F-46454r720120_fix'
  tag 'documentable'
  tag cci: ['CCI-001444']
  tag nist: ['AC-18 (1)']
end
