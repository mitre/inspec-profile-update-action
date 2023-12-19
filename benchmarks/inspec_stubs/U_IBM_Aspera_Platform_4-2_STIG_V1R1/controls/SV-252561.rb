control 'SV-252561' do
  title 'IBM Aspera Console must be configured with a preestablished trust relationship and mechanisms with appropriate authorities (e.g., Active Directory or AAA server) which validate user account access authorizations and privileges.'
  desc 'User account and privilege validation must be centralized in order to prevent unauthorized access using changed or revoked privileges.

IBM Aspera Console must use an IdP for authentication for security best practices. The IdP must not be installed on the IBM Aspera Console virtual machine, particularly if it resides on the untrusted zone of the Enclave. Refer to the IBM Aspera Console Admin Guide for data requirements for the SAML assertion including default attribute names, the IBM Aspera Console User Field, and required format within the assertion. For security best practices also ensure that the system hosting IBM Aspera Console uses Network Time Protocol or another system to keep times synchronized with the IdP/SAML Provider providing the SAML assertions. Clock drift between The IBM Aspera Console server and the IdP/SAML Provider will result in expired assertions and the inability to be successfully authenticated into IBM Aspera Console.

'
  desc 'check', 'Using a web browser, navigate to the IBM Aspera Console web page. IBM Aspera Console will automatically redirect to the IdP for authentication if it is configured for SAML authentication.

If it does not redirect for authentication via the configured IdP, this is a finding.

If redirected to the IdP login page, attempt to authenticate using the IdP with known working credentials to determine if the IdP is providing an appropriate SAML assertion for access.

If unable to log in using known working credentials, this is a finding.'
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
  tag check_id: 'C-56017r817851_chk'
  tag severity: 'medium'
  tag gid: 'V-252561'
  tag rid: 'SV-252561r817853_rule'
  tag stig_id: 'ASP4-CS-040140'
  tag gtitle: 'SRG-NET-000138-ALG-000063'
  tag fix_id: 'F-55967r817852_fix'
  tag satisfies: ['SRG-NET-000138-ALG-000063', 'SRG-NET-000138-ALG-000088', 'SRG-NET-000138-ALG-000089', 'SRG-NET-000140-ALG-000094', 'SRG-NET-000147-ALG-000095']
  tag 'documentable'
  tag cci: ['CCI-000764', 'CCI-000766', 'CCI-001942']
  tag nist: ['IA-2', 'IA-2 (2)', 'IA-2 (9)']
end
