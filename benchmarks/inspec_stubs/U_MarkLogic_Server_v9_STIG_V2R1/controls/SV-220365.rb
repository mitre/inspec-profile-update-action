control 'SV-220365' do
  title 'If passwords are used for authentication, the MarkLogic Server must transmit only encrypted representations of passwords.'
  desc 'The DoD standard for authentication is DoD-approved PKI certificates.

Authentication based on User ID and Password may be used only when it is not possible to employ a PKI certificate, and requires AO approval.

In such cases, passwords must be protected at all times, and encryption is the standard method for protecting passwords during transmission.

DBMS passwords sent in clear text format across the network are vulnerable to discovery by unauthorized users. Disclosure of passwords may easily lead to unauthorized access to the database.

MarkLogic Types of Authentication:
Basic*
Digest
Digest-Basic*
Certificate
Application Level
Kerberos Ticket
SAML
* Indicates that the authentication method allows the username and password to be transmitted in clear text.

For more information on the types of authentication MarkLogic offers, follow this link:
https://docs.marklogic.com/9.0/guide/security/authentication#id_14250'
  desc 'check', 'Review MarkLogic configuration settings for encrypting passwords in transit across the network.

Perform the check from the MarkLogic Server Admin Interface with a user that holds administrative-level privileges.

1. Click the Groups icon.
2. Click the group in which the App Server to be checked resides (e.g., Default).
3. Click the App Servers icon on the left tree menu.
4. Select each of the App Servers.
5. Inspect the selected authentication method, if "basic" or "digest-basic" is selected, this is a finding.

If Application Level is selected and the application server is not configured for SSL, this is a finding'
  desc 'fix', 'If the MarkLogic application server in question is configured with "digest" or "digest-basic" authentication or is configured with "Application Level" authentication and is not SSL enabled, implement the corrective action outlined below. 

Perform the fix from the MarkLogic Server Admin Interface with a user that holds administrative-level privileges.

1. Click the Groups icon.
2. Click the group in which the App Server to be checked resides (e.g., Default).
3. Click the App Servers icon on the left tree menu.
4. Select each of the App Servers.
5. Inspect the selected authentication method, if "basic" or "digest-basic" is selected, change the authentication method to something other than those two.

If Application Level is selected, ensure the application server is configured for SSL.'
  impact 0.7
  ref 'DPMS Target MarkLogic Server v9'
  tag check_id: 'C-22080r401546_chk'
  tag severity: 'high'
  tag gid: 'V-220365'
  tag rid: 'SV-220365r622777_rule'
  tag stig_id: 'ML09-00-003800'
  tag gtitle: 'SRG-APP-000172-DB-000075'
  tag fix_id: 'F-22069r401547_fix'
  tag 'documentable'
  tag legacy: ['V-100975', 'SV-110079']
  tag cci: ['CCI-000197']
  tag nist: ['IA-5 (1) (c)']
end
