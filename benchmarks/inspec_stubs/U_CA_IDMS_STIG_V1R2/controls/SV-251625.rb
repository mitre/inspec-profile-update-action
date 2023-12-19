control 'SV-251625' do
  title 'Custom database code and associated application code must not contain information beyond what is needed for troubleshooting.'
  desc 'Error codes issued by custom code could provide more information than needed for problem resolution and should be vetted to make sure this does not occur.'
  desc 'check', 'Check custom database code to verify that error messages do not contain information beyond what is needed for troubleshooting the issue.

If database errors contain PII data, sensitive business data, or information useful for identifying the host system or database structure, this is a finding.'
  desc 'fix', 'Configure custom database code, and associated application code not to divulge sensitive information or information useful for system identification in error messages.'
  impact 0.5
  ref 'DPMS Target CA IDMS'
  tag check_id: 'C-55060r807740_chk'
  tag severity: 'medium'
  tag gid: 'V-251625'
  tag rid: 'SV-251625r807742_rule'
  tag stig_id: 'IDMS-DB-000540'
  tag gtitle: 'SRG-APP-000266-DB-000162'
  tag fix_id: 'F-55014r807741_fix'
  tag 'documentable'
  tag cci: ['CCI-001312']
  tag nist: ['SI-11 a']
end
