control 'SV-207259' do
  title 'The TLS VPN Gateway that supports citizen- or business-facing network devices must prohibit client negotiation to SSL 2.0 or SSL 3.0.'
  desc 'Using older unauthorized versions or incorrectly configuring protocol negotiation makes the gateway vulnerable to known and unknown attacks that exploit vulnerabilities in this protocol.

This requirement applies to public-facing or external-facing devices such as TLS gateways (also known as SSL gateways), web servers, and web applications. Application protocols such as HTTPS and DNSSEC use TLS as the underlying security protocol and thus are in scope for this requirement. NIST SP 800-52 provides guidance.

The minimum TLS version required by DoD is 1.2. However, devices and applications may allow client negotiation for systems supporting citizen- and business-facing applications. These devices may be configured to support TLS version 1.1 and 1.0 to enable interaction with citizens and businesses. These devices must not support SSL version 3.0 or earlier.'
  desc 'check', 'Verify the TLS VPN Gateway that supports citizen- or business-facing network devices prohibits client negotiation to SSL 2.0 or SSL 3.0.

If the TLS VPN Gateway that supports citizen- or business-facing network devices does not prohibit client negotiation to SSL 2.0 or SSL 3.0, this is a finding.'
  desc 'fix', 'Configure the TLS VPN Gateway that supports citizen- or business-facing network devices to prohibit client negotiation to SSL 2.0 or SSL 3.0.'
  impact 0.5
  ref 'DPMS Target Virtual Private Network (VPN)'
  tag check_id: 'C-7519r378398_chk'
  tag severity: 'medium'
  tag gid: 'V-207259'
  tag rid: 'SV-207259r608988_rule'
  tag stig_id: 'SRG-NET-000540-VPN-002350'
  tag gtitle: 'SRG-NET-000540'
  tag fix_id: 'F-7519r378399_fix'
  tag 'documentable'
  tag legacy: ['SV-106351', 'V-97213']
  tag cci: ['CCI-001453']
  tag nist: ['AC-17 (2)']
end
