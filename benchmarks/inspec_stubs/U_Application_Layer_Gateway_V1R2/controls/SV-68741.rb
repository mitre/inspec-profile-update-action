control 'SV-68741' do
  title 'The ALG that is part of a CDS must enforce information flow control using organization-defined security policy filters as a basis for flow control decisions for organization-defined information flows.'
  desc 'The use of security policy filters provides protection for the confidentiality of data by restricting the flow of data.

Configure organization-defined specific filters and their order of execution for each information flow. For example, security policy filters may include data content filtering rules that monitor for and block specific words (e.g., key word indicators such as terms associated with classified mission), enumerated values, or data value ranges, and hidden content.

Organization-defined security policy filter and organization-defined information flows used as part of a CDS system depend on the environment, data, and security boundaries. Organizations implementing CDS must follow the DoD-required process of testing, baselining, and risk assessment to ensure the rigor and accuracy necessary to rely upon a CDS for cross domain security.'
  desc 'check', 'If the ALG is not part of a CDS, this is not applicable.

Verify the ALG is configured to enforce information flow control using organization-defined security policy filters as a basis for flow control decisions for organization-defined information flows.

If the ALG is not configured to enforce information flow control using organization-defined security policy filters as a basis for flow control decisions for organization-defined information flows, this is a finding.'
  desc 'fix', 'If the ALG is part of a CDS, configure the ALG to enforce information flow control using organization-defined security policy filters as a basis for flow control decisions for organization-defined information flows.'
  impact 0.5
  ref 'DPMS Target SRG-NET-ALG'
  tag check_id: 'C-55111r1_chk'
  tag severity: 'medium'
  tag gid: 'V-54495'
  tag rid: 'SV-68741r1_rule'
  tag stig_id: 'SRG-NET-000033-ALG-000083'
  tag gtitle: 'SRG-NET-000033-ALG-000083'
  tag fix_id: 'F-59349r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000032', 'CCI-000366']
  tag nist: ['AC-4 (8) (a)', 'CM-6 b']
end
