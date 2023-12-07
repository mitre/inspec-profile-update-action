control 'SV-224172' do
  title 'When using command-line tools such as psql, users must use a logon method that does not expose the password.'
  desc 'To prevent the compromise of authentication information, such as passwords and PINs, during the authentication process, the feedback from the information system must not provide any information that would allow an unauthorized user to compromise the authentication mechanism.

Obfuscation of user-provided information when typed into the system is a method used in addressing this risk.

For example, displaying asterisks when a user types in a password or PIN, is an example of obscuring feedback of authentication information.

This requirement is applicable when md5-based password authentication is enabled. When this is the case, password-authenticated accounts can be created in and authenticated by EDB Postgres Advanced Server. Other STIG requirements prohibit the use of password authentication except when justified and approved. This deals with the exceptions.

The psql command line tool is part of any PostgreSQL installation. Other command-line tools may also exist. These tools can accept a plain-text password, but do offer alternative techniques. Since the typical user of these tools is a database administrator, the consequences of password compromise are particularly serious. Therefore, the use of plain-text passwords must be prohibited, as a matter of practice and procedure.'
  desc 'check', 'For psql, which cannot be configured not to accept a plain-text password, and any other essential tool with the same limitation, verify that the system documentation explains the need for the tool, who uses it, and any relevant mitigations and that AO approval has been obtained. If not, this is a finding.

Request evidence that all users of the tool are trained in the importance of using the "-W" option (and not using the plain-text password option), how to keep the password hidden, and that they adhere to this practice. If not, this is a finding.'
  desc 'fix', 'For psql, which can accept a plain-text password, and any other essential tool with the same limitation:

1) Document the need for it, who uses it, and any relevant mitigations, and obtain AO approval.
2) Train all users of the tool in the importance of not using the plain-text password option and in how to keep the password hidden by using the "-W" option.'
  impact 0.7
  ref 'DPMS Target EDB Postgres Advanced Server v11 on Windows'
  tag check_id: 'C-25845r495534_chk'
  tag severity: 'high'
  tag gid: 'V-224172'
  tag rid: 'SV-224172r508023_rule'
  tag stig_id: 'EP11-00-004820'
  tag gtitle: 'SRG-APP-000178-DB-000083'
  tag fix_id: 'F-25833r495535_fix'
  tag 'documentable'
  tag legacy: ['SV-109475', 'V-100371']
  tag cci: ['CCI-000206']
  tag nist: ['IA-6']
end
