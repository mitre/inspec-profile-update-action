control 'SV-220364' do
  title 'If MarkLogic Server authentication using passwords is employed, MarkLogic Server must enforce the DoD standards for password complexity and lifetime.'
  desc 'OS/enterprise authentication and identification must be used (SRG-APP-000023-DB-000001). Native DBMS authentication may be used only when circumstances make it unavoidable, and must be documented and AO-approved.

The DoD standard for authentication is DoD-approved PKI certificates. Authentication based on User ID and Password may be used only when it is not possible to employ a PKI certificate, and requires AO approval.

In such cases, the DoD standards for password complexity and lifetime must be implemented. DBMS products that can inherit the rules for these from the operating system or access control program (e.g., Microsoft Active Directory) must be configured to do so. For other DBMSs, the rules must be enforced using available configuration parameters or custom code.

Types of Authentication
Control the authentication scheme for HTTP, WebDAV, ODBC, and XDBC App Servers.
- Basic authentication is the typical authentication scheme for web applications. A user is prompted for a username and password when accessing an application page. In basic mode, the password is obfuscated but not encrypted.
- Digest authentication works the same way as basic, but offers encryption of passwords sent over the network. A user is prompted for a username and password when accessing an application page.
- The digest-basic authentication scheme uses the more secure digest scheme whenever possible, but reverts to basic authentication when needed. Some older browsers, for example, do not support digest authentication. The digest-basic scheme is also useful if basic authentication was previously used, but must be migrated to digest. The first time a user accesses the server after changing from basic to digest-basic authentication scheme, the server computes the digest password by extracting the relevant information from the credentials supplied in basic mode
- Certificate-based authentication requires internal and external users and HTTPS clients to authenticate to MarkLogic Server via a client certificate, either in addition to, or rather than a password
- Application-level authentication bypasses all authentication and automatically logs all users in as a specified default user. Specify the default user in the Admin Interface, and any users accessing the server automatically inherit the security attributes (roles, privileges, default permissions) of the default user. Application-level authentication is available on HTTP, ODBC, and WebDAV servers.
- In Kerberos Ticket, the user is authenticated by Kerberos and a Kerberos session ticket is used to authenticate the user to access MarkLogic Server.
- When SAML authentication is used, a client requests a resource from MarkLogic Server with no security context. MarkLogic redirects the authentication request to an Identity Provider, the Identity Provider prompts the user to login, if necessary, and sends the authentication request back to MarkLogic Server (the Service Provider) for validation.'
  desc 'check', 'Review MarkLogic settings to see if password authentication is being used, and whether password complexity and lifetime rules are being enforced.

Check for MarkLogic Password Plugin from the MarkLogic Query Console with a user that holds administrative-level privileges.
1. Select "XQuery" in the Query Type drop down and copy the following code into the window:
xquery version "1.0-ml"; 
import module namespace plugin = "http://marklogic.com/extension/plugin" at "/MarkLogic/plugin/plugin.xqy";

plugin:plugins("http://marklogic.com/xdmp/security/password-check")
2. Run the script. If the script returns "your query returned an empty sequence", then no password plugin is present.
3. If the script returns a file name or file names (e.g., password-check-minimum-length.xqy), then review the file/s in the <MarkLogic Home>/Plugins directory to verify compliance with DoD minimum password requirements.
4. Log in to the MarkLogic Server Admin Interface with a user that holds administrative-level privileges.
5. Click the Groups icon.
6. Click the group in which the App Server to be checked resides (e.g., Default).
7. Click the App Servers icon on the left tree menu.
8. Select each of the App Servers.
9. Inspect the selected authentication method, if "basic", "digestbasic", or "digest" is selected and there is not a custom password plugin, or if the password plugin does not meet DoD minimum requirements, this is a finding.'
  desc 'fix', "If the use of passwords is not needed, configure MarkLogic to prevent password use.

If the DBMS can inherit password complexity rules from the operating system or access control program, configure it to do so using one of the following methods: 
1. Configure the MarkLogic server to use Kerberos, SAML or Certificate based authentication. 
2. Develop plugin to enforce password complexity. Examples can be found in MarkLogic Application Developers Guide.

Plugins must enforce the following rules for passwords:

a. minimum of 15 characters, including at least one of each of the following character sets:
- Upper-case
- Lower-case
- Numeric
- Special characters (e.g., ~ ! @ # $ % ^ & * ( ) _ + = - ' [ ] / ? > <)
b. Minimum number of characters changed from previous password: 50 percent of the minimum password length (eight)
c. Password lifetime limits for interactive accounts: Minimum 24 hours, maximum 60 days
d. Password lifetime limits for non-interactive accounts: Minimum 24 hours, maximum 365 days
e. Number of password changes before an old one may be reused: Minimum of five

Develop a custom extension that enforces the password complexity and lifetime.
See https://docs.marklogic.com/guide/app-dev/plugins#id_91783"
  impact 0.5
  ref 'DPMS Target MarkLogic Server v9'
  tag check_id: 'C-22079r401543_chk'
  tag severity: 'medium'
  tag gid: 'V-220364'
  tag rid: 'SV-220364r622777_rule'
  tag stig_id: 'ML09-00-003600'
  tag gtitle: 'SRG-APP-000164-DB-000401'
  tag fix_id: 'F-22068r401544_fix'
  tag 'documentable'
  tag legacy: ['SV-110075', 'V-100971']
  tag cci: ['CCI-000192']
  tag nist: ['IA-5 (1) (a)']
end
