control 'SV-251228' do
  title 'Redis Enterprise DBMS must obscure feedback of authentication information during the authentication process to protect the information from possible exploitation/use by unauthorized individuals.'
  desc 'The DoD standard for authentication is DoD-approved PKI certificates.

Normally, with PKI authentication, the interaction with the user for authentication will be handled by a software component separate from the DBMS, such as ActivID ActivClient. However, in cases where the DBMS controls the interaction, this requirement applies.

To prevent the compromise of authentication information such as passwords and PINs during the authentication process, the feedback from the system must not provide any information that would allow an unauthorized user to compromise the authentication mechanism. 

Obfuscation of user-provided authentication secrets when typed into the system is a method used in addressing this risk. 

Displaying asterisks when a user types in a password or a smart card PIN is an example of obscuring feedback of authentication secrets.

This calls for review of applications, which will require collaboration with the application developers. It is recognized that in many cases, the database administrator (DBA) is organizationally separate from the application developers, and may have limited, if any, access to source code. Nevertheless, protections of this type are so important to the secure operation of databases that they must not be ignored. At a minimum, the DBA must attempt to obtain assurances from the development organization that this issue has been addressed and must document what has been discovered.'
  desc 'check', 'If all interaction with the user for purposes of authentication is handled by a software component separate from the DBMS, this is not a finding.

The Redis Enterprise web UI does inherently obscure passwords. For Redis CLI, which cannot be configured not to accept a plain-text password, and any other essential tool with the same limitation, verify that the system documentation explains the need for the tool, who uses it, and any relevant mitigations and that AO approval has been obtained. If not, this is a finding.

Request evidence that all users of the tool are trained in the importance of using the "--askpass" option (and not using the plain-text password option), how to keep the password hidden, and that they adhere to this practice. If not, this is a finding.'
  desc 'fix', 'For Redis CLI tools, which can accept a plain-text password, and any other essential tool with the same limitation:
1. Document the need for it, who uses it, and any relevant mitigations, and obtain AO approval.
2. Train all users of the tool in the importance of not using the plain-text password option and in how to keep the password hidden by using the "--askpass" without the password option. The user will then be prompted and the password obfuscated.

Example command for authentication:
redis-cli -h <db_endpoint> -p <port> --askpass'
  impact 0.7
  ref 'DPMS Target Redis Enterprise 6.x'
  tag check_id: 'C-54663r804872_chk'
  tag severity: 'high'
  tag gid: 'V-251228'
  tag rid: 'SV-251228r804874_rule'
  tag stig_id: 'RD6X-00-009400'
  tag gtitle: 'SRG-APP-000178-DB-000083'
  tag fix_id: 'F-54617r804873_fix'
  tag 'documentable'
  tag cci: ['CCI-000206']
  tag nist: ['IA-6']
end
