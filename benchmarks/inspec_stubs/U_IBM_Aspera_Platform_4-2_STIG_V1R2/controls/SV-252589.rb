control 'SV-252589' do
  title 'IBM Aspera Faspex must be configured to uniquely identify and authenticate organizational users (or processes acting on behalf of organizational users).'
  desc "To ensure accountability and prevent unauthenticated access, organizational users must be identified and authenticated to prevent potential misuse and compromise of the system.

Organizational users include organizational employees or individuals the organization deems to have equivalent status of employees (e.g., contractors). Organizational users (and any processes acting on behalf of users) must be uniquely identified and authenticated for all accesses except the following.

1) Accesses explicitly identified and documented by the organization. Organizations document specific user actions that can be performed on the information system without identification or authentication.

2) Accesses that occur through authorized use of group authenticators without individual authentication. Organizations may require unique identification of individuals in group accounts (e.g., shared privilege accounts) or for detailed accountability of individual activity.

This requirement applies to ALGs that provide user proxy services, including identification and authentication. This service must use the site's directory service (e.g., Active Directory). Directory services must not be installed onto the gateway.

IBM Aspera Faspex will list preestablished trust relationships for IdPs on the default Faspex login page. This configuration supports the ability to have more than one preestablished trust relationship, and it requires the user to choose from the valid preestablished IdPs as listed on the default web page. If IBM Aspera Faspex is configured to automatically redirect to a single IdP, visiting the default webpage will do so. Refer to the IBM Aspera Faspex Admin Guide for data requirements for the SAML assertion including default attribute names, the IBM Faspex User Field, and required format within the assertion. For security best practices, also ensure that the system hosting Aspera Faspex uses Network Time Protocol or another system to keep times synchronized with the IdP server providing the SAML assertions. Clock drift between the IBM Aspera Faspex server and the IdP/SAML Provider will result in expired assertions and the inability to be successfully authenticated into IBM Aspera Faspex.

"
  desc 'check', 'If the IBM Aspera Faspex feature of the Aspera Platform is not installed, this is Not Applicable.

Using a web browser, navigate to the default IBM Aspera Faspex web page.

If you are neither redirected to an IdP nor provided with a list of one or more IdPs to choose from on the standard IBM Aspera Faspex webpage, this is a finding.

If redirected to the IdP login, attempt to authenticate using the IdP with known working credentials to determine if the IdP is providing an appropriate SAML assertion for access.

If unable to log in using known working credentials, this is a finding.

If not redirected to a single IdP but provided a list of configured IdPs, choose one for authentication with known working credentials to determine if the IdP is providing an appropriate SAML assertion for access.

If unable to log in using known working credentials, this is a finding.'
  desc 'fix', %q(For implementations using the IBM Aspera Faspex feature, configure SAML to use an existing IdP.

To configure SAML within IBM Aspera Faspex, perform the following:

- Log in to the IBM Aspera Faspex web page as a user with administrative privilege.
- Select the "Server" tab.
- Select the "Authentication" tab.
- Select the SAML Integration menu.
- Select "Add New SAML Configuration".
- Choose one action from these: 1) Enter the SAML server's metadata URL in "Import from URL" and click "Import Setting From Metadata URL". 2) Click "Browse" and locate the file containing the SAML server's metadata. 3) Paste the SAML server metadata into the box labeled "Import from Text" and click the "Import Settings From Text".
- Select "Create SAML Configuration" at the bottom of the page.)
  impact 0.5
  ref 'DPMS Target IBM Aspera Platform 4.2'
  tag check_id: 'C-56045r817935_chk'
  tag severity: 'medium'
  tag gid: 'V-252589'
  tag rid: 'SV-252589r831504_rule'
  tag stig_id: 'ASP4-FA-050250'
  tag gtitle: 'SRG-NET-000138-ALG-000063'
  tag fix_id: 'F-55995r817936_fix'
  tag satisfies: ['SRG-NET-000138-ALG-000063', 'SRG-NET-000138-ALG-000088', 'SRG-NET-000138-ALG-000089', 'SRG-NET-000140-ALG-000094', 'SRG-NET-000147-ALG-000095']
  tag 'documentable'
  tag cci: ['CCI-000764', 'CCI-000766', 'CCI-001942']
  tag nist: ['IA-2', 'IA-2 (2)', 'IA-2 (9)']
end
