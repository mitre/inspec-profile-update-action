control 'SV-253523' do
  title 'Access to Prisma Cloud Compute must be managed based on user need and least privileged  using external identity providers for authentication and grouping to role-based assignments when possible.'
  desc "Integration with an organization's existing identity management policies technologies reduces the threat of account compromise and misuse.

Centralized authentication services provide additional functionality to fulfill security requirements:
- Multifactor authentication, which is compatible with Rancher MCM.
- Disabling users after a period of time.
- Encrypted storage and transmission of secure information.
- Secure authentication protocols such as LDAP over TLS or LDAPS using FIPS 140-2 approved encryption modules.
- PKI-based authentication.

"
  desc 'check', %q(Confirm the Prisma Cloud Console has been configured from SAML-based authentication.

Navigate to Prisma Cloud Compute Console's Manage >> Authentication >> Identity Providers tab. 

Verify SAML settings are "Enabled" and an identity provider has been configured.

If SAML settings are not enabled and an identity provider has not been configured, this is a finding.)
  desc 'fix', %q(Configure Prisma Cloud Console for SAML-based authentication in which the SAML IdP enforces multifactor authentication (e.g., x509/smartcard authentication). 

Navigate to Prisma Cloud Compute Console's Manage >> Authentication >> Identity Providers:
- Click "Add provider".
- For Protocol, select "SAML".
- For Identity provider, select provider. 
- Configure the settings and click "Save".
  SAML settings = Enabled 
 
Configure an SAML identity provider that enforces privileged account multifactor authentication for the Prisma Cloud Compute service provider.)
  impact 0.5
  ref 'DPMS Target Palo Alto Networks Prisma Cloud Compute'
  tag check_id: 'C-56975r840405_chk'
  tag severity: 'medium'
  tag gid: 'V-253523'
  tag rid: 'SV-253523r879522_rule'
  tag stig_id: 'CNTR-PC-000030'
  tag gtitle: 'SRG-APP-000023-CTR-000055'
  tag fix_id: 'F-56926r840406_fix'
  tag satisfies: ['SRG-APP-000023-CTR-000055', 'SRG-APP-000024-CTR-000060', 'SRG-APP-000025-CTR-000065', 'SRG-APP-000033-CTR-000095', 'SRG-APP-000065-CTR-000115', 'SRG-APP-000068-CTR-000120', 'SRG-APP-000069-CTR-000125', 'SRG-APP-000149-CTR-000355', 'SRG-APP-000150-CTR-000360', 'SRG-APP-000151-CTR-000365', 'SRG-APP-000152-CTR-000370', 'SRG-APP-000163-CTR-000395', 'SRG-APP-000165-CTR-000405', 'SRG-APP-000170-CTR-000430', 'SRG-APP-000173-CTR-000445', 'SRG-APP-000174-CTR-000450', 'SRG-APP-000291-CTR-000675', 'SRG-APP-000292-CTR-000680', 'SRG-APP-000293-CTR-000685', 'SRG-APP-000294-CTR-000690', 'SRG-APP-000317-CTR-000735', 'SRG-APP-000318-CTR-000740', 'SRG-APP-000345-CTR-000785', 'SRG-APP-000397-CTR-000955']
  tag 'documentable'
  tag cci: ['CCI-000015', 'CCI-000016', 'CCI-000017', 'CCI-000044', 'CCI-000048', 'CCI-000050', 'CCI-000195', 'CCI-000198', 'CCI-000199', 'CCI-000200', 'CCI-000213', 'CCI-000765', 'CCI-000766', 'CCI-000767', 'CCI-000768', 'CCI-000795', 'CCI-001683', 'CCI-001684', 'CCI-001685', 'CCI-001686', 'CCI-002041', 'CCI-002142', 'CCI-002145', 'CCI-002238']
  tag nist: ['AC-2 (1)', 'AC-2 (2)', 'AC-2 (3) (d)', 'AC-7 a', 'AC-8 a', 'AC-8 b', 'IA-5 (1) (b)', 'IA-5 (1) (d)', 'IA-5 (1) (d)', 'IA-5 (1) (e)', 'AC-3', 'IA-2 (1)', 'IA-2 (2)', 'IA-2 (3)', 'IA-2 (4)', 'IA-4 e', 'AC-2 (4)', 'AC-2 (4)', 'AC-2 (4)', 'AC-2 (4)', 'IA-5 (1) (f)', 'AC-2 (10)', 'AC-2 (11)', 'AC-7 b']
end
