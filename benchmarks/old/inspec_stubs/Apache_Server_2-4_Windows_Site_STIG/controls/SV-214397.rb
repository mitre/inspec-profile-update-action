control 'SV-214397' do
  title 'The Apache web server must be configured in accordance with the security configuration settings based on DoD security configuration or implementation guidance, including STIGs, NSA configuration guides, CTOs, and DTMs.'
  desc 'Configuring the web server to implement organization-wide security implementation guides and security checklists guarantees compliance with federal standards and establishes a common security baseline across the DoD that reflects the most restrictive security posture consistent with operational requirements. 

Configuration settings are the set of parameters that can be changed that affect the security posture and/or functionality of the system. Security-related parameters are parameters impacting the security state of the web server, including the parameters required to satisfy other security control requirements.'
  desc 'check', 'Review the website to determine if "HTTP" and "HTTPS" are used in accordance with well-known ports (e.g., 80 and 443) or those ports and services as registered and approved for use by the DoD PPSM. 

Verify that any variation in PPS is documented, registered, and approved by the PPSM.

If it is not, this is a finding.'
  desc 'fix', 'Ensure the website enforces the use of IANA well-known ports for "HTTP" and "HTTPS".'
  impact 0.3
  ref 'DPMS Target Apache Server 2.4 Windows Site'
  tag check_id: 'C-15608r277932_chk'
  tag severity: 'low'
  tag gid: 'V-214397'
  tag rid: 'SV-214397r401224_rule'
  tag stig_id: 'AS24-W2-000950'
  tag gtitle: 'SRG-APP-000516-WSR-000174'
  tag fix_id: 'F-15606r277933_fix'
  tag 'documentable'
  tag legacy: ['SV-102683', 'V-92595']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
