control 'SV-204808' do
  title 'The application server must accept FICAM-approved third-party credentials.'
  desc 'Access may be denied to legitimate users if FICAM-approved third-party credentials are not accepted.

This requirement typically applies to organizational information systems that are accessible to non-federal government agencies and other partners. This allows federal government relying parties to trust such credentials at their approved assurance levels.

Third-party credentials are those credentials issued by non-federal government entities approved by the Federal Identity, Credential, and Access Management (FICAM) Trust Framework Solutions initiative.'
  desc 'check', 'Review the application server documentation and configuration to determine if the application server accepts FICAM-approved third-party credentials.

If the application server does not accept FICAM-approved third-party credentials, this is a finding.'
  desc 'fix', 'Configure the application server to accept FICAM-approved third-party credentials.'
  impact 0.5
  ref 'DPMS Target Application Server'
  tag check_id: 'C-4928r283065_chk'
  tag severity: 'medium'
  tag gid: 'V-204808'
  tag rid: 'SV-204808r850861_rule'
  tag stig_id: 'SRG-APP-000404-AS-000249'
  tag gtitle: 'SRG-APP-000404'
  tag fix_id: 'F-4928r283066_fix'
  tag 'documentable'
  tag legacy: ['SV-71795', 'V-57519']
  tag cci: ['CCI-002011']
  tag nist: ['IA-8 (2)']
end
