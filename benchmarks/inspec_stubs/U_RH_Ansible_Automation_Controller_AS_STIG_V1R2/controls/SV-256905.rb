control 'SV-256905' do
  title 'Automation Controller must be configured to use an enterprise user management system.'
  desc 'Unauthenticated application servers render the organization subject to exploitation. Therefore, application servers must be uniquely identified and authenticated to prevent unauthorized access.

'
  desc 'check', 'The Administrator must check the Automation Controller web administrator console and verify the appropriate authentication provider is configured and the associated fields are complete and accurate.

Log in to Automation Controller as an administrator and navigate to Settings >> Authentication.

If the organization-defined identity provider is not configured, or any associated fields are incomplete or inaccurate, this is a finding.'
  desc 'fix', 'Log in to Automation Controller as an administrator and navigate to Settings >> Authentication.

Configure the appropriate authentication provider and associated fields for the organization-defined identity provider:

Click on LDAP settings.

Click "Edit".

Configure/complete the fields.

Click "Save".'
  impact 0.5
  ref 'DPMS Target Red Hat Ansible Automation Controller App Server'
  tag check_id: 'C-60580r902283_chk'
  tag severity: 'medium'
  tag gid: 'V-256905'
  tag rid: 'SV-256905r903508_rule'
  tag stig_id: 'APAS-AT-000047'
  tag gtitle: 'SRG-APP-000148-AS-000101'
  tag fix_id: 'F-60522r903507_fix'
  tag satisfies: ['SRG-APP-000148-AS-000101', 'SRG-APP-000149-AS-000102', 'SRG-APP-000151-AS-000103', 'SRG-APP-000177-AS-000126', 'SRG-APP-000389-AS-000253', 'SRG-APP-000390-AS-000254', 'SRG-APP-000391-AS-000239', 'SRG-APP-000392-AS-000240', 'SRG-APP-000400-AS-000246', 'SRG-APP-000401-AS-000243', 'SRG-APP-000402-AS-000247', 'SRG-APP-000403-AS-000248', 'SRG-APP-000404-AS-000249', 'SRG-APP-000405-AS-000250']
  tag 'documentable'
  tag cci: ['CCI-000187', 'CCI-000764', 'CCI-000765', 'CCI-000767', 'CCI-001953', 'CCI-001954', 'CCI-001991', 'CCI-002007', 'CCI-002009', 'CCI-002010', 'CCI-002011', 'CCI-002014', 'CCI-002038', 'CCI-002039']
  tag nist: ['IA-5 (2) (a) (2)', 'IA-2', 'IA-2 (1)', 'IA-2 (3)', 'IA-2 (12)', 'IA-2 (12)', 'IA-5 (2) (d)', 'IA-5 (13)', 'IA-8 (1)', 'IA-8 (1)', 'IA-8 (2)', 'IA-8 (4)', 'IA-11', 'IA-11']
end
