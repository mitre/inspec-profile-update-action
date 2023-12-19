control 'SV-237724' do
  title 'The DBMS must ensure users are authenticated with an individual authenticator prior to using a shared authenticator.'
  desc "To assure individual accountability and prevent unauthorized access, application users (and any processes acting on behalf of users) must be individually identified and authenticated.

A shared authenticator is a generic account used by multiple individuals. Use of a shared authenticator alone does not uniquely identify individual users. An example of a shared authenticator is the UNIX OS 'root' user account, a Windows 'administrator' account, an 'SA' account, or a 'helpdesk' account.

For example, the UNIX and Windows operating systems offer a 'switch user' capability allowing users to authenticate with their individual credentials and, when needed, 'switch' to the administrator role. This method provides for unique individual authentication prior to using a shared authenticator.

Some applications may not have the need to provide a group authenticator; this is considered a matter of application design. In those instances where the application design includes the use of a shared authenticator, this requirement will apply.

There may also be instances when specific user actions need to be performed on the information system without unique user identification or authentication. An example of this type of access is a web server which contains publicly releasable information. These types of accesses are allowed but must be explicitly identified and documented by the organization.

When shared accounts are utilized without another means of identifying individual users, users may deny having performed a particular action."
  desc 'check', 'Review DBMS settings, OS settings, and/or enterprise-level authentication/access mechanism settings to determine whether shared accounts exist. If group accounts do not exist, this is NA.

Review DBMS settings to determine if individual authentication is required before shared authentication.

If shared authentication does not require prior individual authentication, this is a finding.

(Oracle Access Manager may be helpful in meeting this requirement. Notes on Oracle Access Manager follow.)

Oracle Access Manager is used when there is a need for multifactor authentication of applications front-ending Oracle Datasets that may use group accounts. Oracle Access Manager supports using PKI-based smart cards (CAC, PIV) for multifactor authentication. When a user authenticates to a smart card application, the smart card engine produces a certificate-based authentication token. Can configure a certificate-based authentication scheme in Oracle Access Manager that uses information from the smart card certificate. Certificate-based authentication works with any smart card or similar device that presents an X.509 certificate.

Check:
First, check that the Authentication Module is set up properly:
1) Go to Oracle Access Manager Home Screen and click the Policy Configuration tab.  Select the X509Scheme.
2) Make sure the Authentication Module option is set to X509Plugin.

Second, check that the Authentication policy is using the x509Scheme:
1) Go to Oracle Access Manager Home Screen and click the Policy Configuration tab.
2) Select Application Domains.  Select Search.
3) Select the application domain protecting the Oracle Database.
4) Select the Authentication Polices tab and Click Protected Resource Policy.
5) Make sure the Authentication Scheme is set to x509Scheme.'
  desc 'fix', 'Configure DBMS, OS and/or enterprise-level authentication/access mechanism to require individual authentication prior to authentication for shared account access.

If appropriate, install Oracle Access Manager to provide multifactor authentication of applications front-ending Oracle Databases and using shared accounts.  After installation, use x509 Authentication modules provided out of the box.'
  impact 0.5
  ref 'DPMS Target Oracle Database 12c'
  tag check_id: 'C-40943r667202_chk'
  tag severity: 'medium'
  tag gid: 'V-237724'
  tag rid: 'SV-237724r667204_rule'
  tag stig_id: 'O121-C2-013300'
  tag gtitle: 'SRG-APP-000148-DB-000103'
  tag fix_id: 'F-40906r667203_fix'
  tag 'documentable'
  tag legacy: ['V-61711', 'SV-76201']
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end
