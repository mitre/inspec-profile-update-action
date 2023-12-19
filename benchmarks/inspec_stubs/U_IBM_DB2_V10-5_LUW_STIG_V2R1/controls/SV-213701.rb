control 'SV-213701' do
  title 'When using command-line tools such as db2, users must use a Connect method that does not expose the password.'
  desc 'To prevent the compromise of authentication information, such as passwords and PINs, during the authentication process, the feedback from the information system must not provide any information that would allow an unauthorized user to compromise the authentication mechanism.

Obfuscation of user-provided information when typed into the system is a method used in addressing this risk.

For example, displaying asterisks when a user types in a password or PIN, is an example of obscuring feedback of authentication information.

"db2" and other command-line tools are part of any DB2 for LUW installation. These tools can accept a plain-text password, but do offer alternative techniques. Since the typical user of these tools is a database administrator, the consequences of password compromise are particularly serious. Therefore, the use of plain-text passwords must be prohibited, as a matter of practice and procedure.'
  desc 'check', 'For the "db2" command, which cannot be configured not to accept a plain-text password, and any other essential tool with the same limitation, verify that the system documentation explains the need for the tool, who uses it, and any relevant mitigations; and that AO approval has been obtained; if not, this is a finding.

Request evidence that all users of the tool are trained in the importance of not using the plain-text password option and in how to keep the password hidden; and that they adhere to this practice. If not, this is a finding.'
  desc 'fix', 'For the "db2" command, which cannot be configured not to accept a plain-text password, and any other essential tool with the same limitation:
1) Document the need for it, who uses it, and any relevant mitigations, and obtain AO approval.
2) Train all users of the tool in the importance of not using the plain-text password option and in how to keep the password hidden.'
  impact 0.7
  ref 'DPMS Target IBM DB2 V10.5 LUW'
  tag check_id: 'C-14922r295152_chk'
  tag severity: 'high'
  tag gid: 'V-213701'
  tag rid: 'SV-213701r879615_rule'
  tag stig_id: 'DB2X-00-004520'
  tag gtitle: 'SRG-APP-000178-DB-000083'
  tag fix_id: 'F-14920r295153_fix'
  tag 'documentable'
  tag legacy: ['SV-89165', 'V-74491']
  tag cci: ['CCI-000206']
  tag nist: ['IA-6']
end
