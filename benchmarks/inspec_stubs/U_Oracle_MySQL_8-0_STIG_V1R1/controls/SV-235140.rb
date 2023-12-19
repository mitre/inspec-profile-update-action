control 'SV-235140' do
  title 'The MySQL Database Server 8.0 must obscure feedback of authentication information during the authentication process to protect the information from possible exploitation/use by unauthorized individuals.'
  desc 'The DoD standard for authentication is DoD-approved PKI certificates.

Normally, with PKI authentication, the interaction with the user for authentication will be handled by a software component separate from the Database Management System (DBMS), such as ActivIdentity ActivClient. However, in cases where the DBMS controls the interaction, this requirement applies.

To prevent the compromise of authentication information such as passwords and PINs during the authentication process, the feedback from the system must not provide any information that would allow an unauthorized user to compromise the authentication mechanism. 

Obfuscation of user-provided authentication secrets when typed into the system is a method used in addressing this risk. 

Displaying asterisks when a user types in a password or a smart card PIN is an example of obscuring feedback of authentication secrets.

For mysql tools, which can accept a plain-text password, and any other essential tool with the same limitation:
1) Document the need for it, who uses it, and any relevant mitigations, and obtain Authorizing Official (AO) approval
2) Train all users of the tool in the importance of not using the plain-text password option and in how to keep the password hidden by using the "-p" without the password option. The user will then be prompted and the password obfuscated.
3) Make use of OS pluggable password manager integration to protect passwords using keyrings'
  desc 'check', 'If all interaction with the user for purposes of authentication is handled by a software component separate from the MySQL Database Server 8.0, this is not a finding.

If any application, tool, or feature associated with the MySQL Database Server 8.0/database displays any authentication secrets (to include PINs and passwords) during or after the authentication process, this is a finding.

MySQL command line option --password (or -p) obscures feedback on the typed in password. 

Ensure users are trained to use alternatives to command line password parameters, if they are not, this is a finding.'
  desc 'fix', "Modify and configure each non-compliant application, tool, or feature associated with the MySQL Database Server 8.0/database so that it does not display authentication secrets.

Use -p (--password) without providing a password for the mysql command line tool.

Configure or modify applications to prohibit display of passwords in clear text.

Use OS pluggable password manager integration to protect passwords using keyrings. Following is an example:
$ /usr/local/mysql/bin/mysql -uroot -p
Enter password:

$ mysqlsh --user=user --password
Please provide the password for 'user@localhost':"
  impact 0.7
  ref 'DPMS Target Oracle MySQL 8.0'
  tag check_id: 'C-38359r623540_chk'
  tag severity: 'high'
  tag gid: 'V-235140'
  tag rid: 'SV-235140r638812_rule'
  tag stig_id: 'MYS8-00-005300'
  tag gtitle: 'SRG-APP-000178-DB-000083'
  tag fix_id: 'F-38322r623541_fix'
  tag 'documentable'
  tag cci: ['CCI-000206']
  tag nist: ['IA-6']
end
