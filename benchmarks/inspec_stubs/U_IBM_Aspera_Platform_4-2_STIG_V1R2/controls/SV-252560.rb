control 'SV-252560' do
  title 'The IBM Aspera Console must protect audit tools from unauthorized access.'
  desc 'Protecting audit data also includes identifying and protecting the tools used to view and manipulate log data. Therefore, protecting audit tools is necessary to prevent unauthorized operation on audit data.

Network elements providing tools to interface with audit data will leverage user permissions and roles identifying the user accessing the tools and the corresponding rights the user enjoys in order make access decisions regarding the access to audit tools.

Audit tools include, but are not limited to, vendor-provided and open source audit tools needed to successfully view and manipulate audit information system activity and records. Audit tools include custom queries and report generators.

This does not apply to audit logs generated on behalf of the device itself (management).

Refer to the IBM Aspera Console Admin Guide for data requirements for the SAML assertion including default attribute names, the IBM Aspera Console User Field, and required format within the assertion.'
  desc 'check', 'Using a web browser, navigate to the IBM Aspera Console web page. The IBM Aspera Console will automatically redirect to the IdP for authentication if it is configured for SAML authentication.

If it does not redirect for authentication via the configured IdP, this is a finding.

If redirected to the IdP login page, attempt to authenticate using the IdP with known working credentials to determine if the IdP is providing an appropriate SAML assertion for access.'
  desc 'fix', 'Configure SAML within the IBM Aspera Console to use an existing IdP with the following steps:

- Log in to the IBM Aspera Console web page as a user with administrative privilege.
- Select the "Accounts" tab.
- Select the "SAML" tab.
- Enter the IdP SSO Target (Redirect) URL.
- Enter the IdP Cert Fingerprint.
- Select from the dropdown menu the IdP Cert Fingerprint Algorithm. 
- Select "Save" at the bottom of the page.'
  impact 0.5
  ref 'DPMS Target IBM Aspera Platform 4.2'
  tag check_id: 'C-56016r817848_chk'
  tag severity: 'medium'
  tag gid: 'V-252560'
  tag rid: 'SV-252560r817850_rule'
  tag stig_id: 'ASP4-CS-040130'
  tag gtitle: 'SRG-NET-000101-ALG-000059'
  tag fix_id: 'F-55966r817849_fix'
  tag 'documentable'
  tag cci: ['CCI-001493']
  tag nist: ['AU-9 a']
end
