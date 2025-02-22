control 'SV-82969' do
  title 'The Mainframe Product must reveal full-text detail error messages only to system programmers and/or security administrators.'
  desc "Only authorized personnel should be aware of errors and the details of the errors. Error messages are an indicator of an organization's operational state or can identify the application. Additionally, Personally Identifiable Information (PII) and operational information must not be revealed through error messages to unauthorized personnel or their designated representatives.

The structure and content of error messages must be carefully considered by the organization and development team. The extent to which the information system is able to identify and handle error conditions is guided by organizational policy and operational requirements."
  desc 'check', 'Examine product documentation and code.

If full text detailed error message are not restricted to system programmers and/or security administrators, this is a finding.'
  desc 'fix', 'Configure the Mainframe Product to restrict full text detailed error message to system programmers and/or security administrators only.'
  impact 0.5
  ref 'DPMS Target SRG-APP-MFPR'
  tag check_id: 'C-69011r1_chk'
  tag severity: 'medium'
  tag gid: 'V-68479'
  tag rid: 'SV-82969r1_rule'
  tag stig_id: 'SRG-APP-000267-MFP-000335'
  tag gtitle: 'SRG-APP-000267-MFP-000335'
  tag fix_id: 'F-74595r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001314']
  tag nist: ['SI-11 b']
end
