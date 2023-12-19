control 'SV-69583' do
  title 'The IDPS must be configured in accordance with the security configuration settings based on DoD security policy and technology-specific security best practices.'
  desc 'Configuring the IDPS to implement organization-wide security implementation guides and security checklists ensures compliance with federal standards and establishes a common security baseline across DoD that reflects the most restrictive security posture consistent with operational requirements.

Configuration settings are the set of parameters that can be changed that affect the security posture and/or functionality of the network element. Security-related parameters are those parameters impacting the security state of the network element, including the parameters required to satisfy other security control requirements. For the network element, security-related parameters include settings for communications traffic management configurations.'
  desc 'check', 'Verify the IDPS is configured in accordance with the security configuration settings based on DoD security policy and technology-specific security best practices.

If the IDPS is not configured in accordance with the security configuration settings based on DoD security policy and technology-specific security best practices, this is a finding.'
  desc 'fix', 'Configure the IDPS to comply with the security configuration settings based on DoD security policy and technology-specific security best practices.'
  impact 0.5
  ref 'DPMS Target SRG-NET-IDPS'
  tag check_id: 'C-55959r1_chk'
  tag severity: 'medium'
  tag gid: 'V-55337'
  tag rid: 'SV-69583r1_rule'
  tag stig_id: 'SRG-NET-000512-IDPS-00194'
  tag gtitle: 'SRG-NET-000512-IDPS-00194'
  tag fix_id: 'F-60203r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
