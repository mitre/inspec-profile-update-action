control 'SV-68719' do
  title 'The ALG that is part of a CDS, when transferring information between different security domains, must implement organization-defined security policy filters requiring fully enumerated formats that restrict data structure and content.'
  desc 'Data structure and content restrictions reduce the range of potential malicious and/or unsanctioned content in cross-domain transactions.

Security policy filters that restrict data structures include, for example, restricting file sizes and field lengths. Data content policy filters include: 

1) Encoding formats for character sets (e.g., Universal Character Set Transformation Formats)
2) American Standard Code for Information Interchange (ASCII)
3) Restricting character data fields to only contain alpha-numeric characters
4) Prohibiting special characters
5) Validating schema structures

Organization-defined security policy filters which require format restrictions depend on the environment, data, and security boundaries. Organizations implementing CDS must follow the DoD-required process of testing, baselining, and risk assessment to ensure the rigor and accuracy necessary to rely upon a CDS for cross domain security.'
  desc 'check', 'If the ALG is not part of a CDS, this is not applicable.

Verify the ALG, when transferring information between different security domains, implements organization-defined security policy filters requiring fully enumerated formats that restrict data structure and content.

If the ALG when transferring information between different security domains does not implement organization-defined security policy filters requiring fully enumerated formats that restrict data structure and content, this is a finding.'
  desc 'fix', 'If the ALG is part of a CDS, configure the ALG to implement organization-defined security policy filters requiring fully enumerated formats that restrict data structure and content when transferring information between different security domains.'
  impact 0.5
  ref 'DPMS Target SRG-NET-ALG'
  tag check_id: 'C-55089r1_chk'
  tag severity: 'medium'
  tag gid: 'V-54473'
  tag rid: 'SV-68719r1_rule'
  tag stig_id: 'SRG-NET-000283-ALG-000072'
  tag gtitle: 'SRG-NET-000283-ALG-000072'
  tag fix_id: 'F-59327r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-001372']
  tag nist: ['CM-6 b', 'AC-4 (14)']
end
