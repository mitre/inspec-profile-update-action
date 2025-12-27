control 'SV-252606' do
  title 'IBM Aspera Shares must be configured to uniquely identify and authenticate organizational users (or processes acting on behalf of organizational users).'
  desc "To assure accountability and prevent unauthenticated access, organizational users must be identified and authenticated to prevent potential misuse and compromise of the system.
Organizational users include organizational employees or individuals the organization deems to have equivalent status of employees (e.g., contractors). Organizational users (and any processes acting on behalf of users) must be uniquely identified and authenticated for all accesses except the following.

1) Accesses explicitly identified and documented by the organization. Organizations document specific user actions that can be performed on the information system without identification or authentication.

2) Accesses that occur through authorized use of group authenticators without individual authentication. Organizations may require unique identification of individuals in group accounts (e.g., shared privilege accounts) or for detailed accountability of individual activity.

This requirement applies to ALGs that provide user proxy services, including identification and authentication. This service must use the site's directory service (e.g., Active Directory). Directory services must not be installed onto the gateway.

Refer to the IBM Aspera Shares Admin Guide for data requirements for the SAML assertion including default attribute names, the IBM Aspera Shares User Field, and required format within the assertion. For security best practices, also ensure that the system hosting IBM Aspera Shares uses Network Time Protocol or another system to keep times synchronized with the IdP/SAML Provider providing the SAML assertions. Clock drift between The IBM Aspera Shares server and the IdP/SAML Provider will result in expired assertions and the inability to be successfully authenticated into IBM Aspera Shares. 

"
  desc 'check', 'If the IBM Aspera Shares feature of the Aspera Platform is not installed, this is Not Applicable.

Using a web browser, navigate to the default IBM Aspera Shares web page. Attempt to authenticate using the IdP provided under "SAML" heading of login page with known working credentials to determine if the IdP is providing an appropriate SAML assertion for access.

If unable to log in using known working credentials, this is a finding.'
  desc 'fix', 'For implementations using the IBM Aspera Shares feature, configure SAML to use an existing IdP.

- Log in to the IBM Aspera Shares web page as a user with administrative privilege. 
- Select the "Admin" tab.
- Go to "Accounts".
- Select the "Directories" option from the left menu.
- Beside the SAML IdP entry, click "Edit".
- To enable SAML, select the check box "Log in using the SAML Identity Provider".
- Enter the SAML entry-point address provided by the IdP in the "IdP Single Sign-On URL" text box.
- Enter the "Identity Provider Certificate Fingerprint" and specify the algorithm type in the dropdown menu.
- Enter the "Identity Provider Certificate".
- Select "Save" at the bottom of the page.'
  impact 0.5
  ref 'DPMS Target IBM Aspera Platform 4.2'
  tag check_id: 'C-56062r817986_chk'
  tag severity: 'medium'
  tag gid: 'V-252606'
  tag rid: 'SV-252606r831512_rule'
  tag stig_id: 'ASP4-SH-060190'
  tag gtitle: 'SRG-NET-000138-ALG-000063'
  tag fix_id: 'F-56012r817987_fix'
  tag satisfies: ['SRG-NET-000138-ALG-000063', 'SRG-NET-000138-ALG-000088', 'SRG-NET-000138-ALG-000089', 'SRG-NET-000140-ALG-000094', 'SRG-NET-000147-ALG-000095']
  tag 'documentable'
  tag cci: ['CCI-000764', 'CCI-000766', 'CCI-001942']
  tag nist: ['IA-2', 'IA-2 (2)', 'IA-2 (9)']
end
