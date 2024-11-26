control 'SV-224171' do
  title 'Applications must obscure feedback of authentication information during the authentication process to protect the information from possible exploitation/use by unauthorized individuals.'
  desc 'The DoD standard for authentication is DoD-approved PKI certificates.

Normally, with PKI authentication, the interaction with the user for authentication will be handled by a software component separate from the DBMS, such as ActivIdentity ActivClient. However, in cases where the DBMS controls the interaction, this requirement applies.

To prevent the compromise of authentication information such as passwords and PINs during the authentication process, the feedback from the system must not provide any information that would allow an unauthorized user to compromise the authentication mechanism. 

Obfuscation of user-provided authentication secrets when typed into the system is a method used in addressing this risk. 

Displaying asterisks when a user types in a password or a smart card PIN is an example of obscuring feedback of authentication secrets.

This calls for review of applications, which will require collaboration with the application developers. It is recognized that in many cases, the database administrator (DBA) is organizationally separate from the application developers, and may have limited, if any, access to source code. Nevertheless, protections of this type are so important to the secure operation of databases that they must not be ignored. At minimum, the DBA must attempt to obtain assurances from the development organization the issue has been addressed, and must document what has been discovered.'
  desc 'check', 'Determine whether any applications that access the database allow for entry of the account name and password or PIN.

If any do, determine whether these applications obfuscate authentication data. If they do not, this is a finding.'
  desc 'fix', 'Configure or modify applications to prohibit display of passwords in clear text.'
  impact 0.7
  ref 'DPMS Target EDB Postgres Advanced Server v11 on Windows'
  tag check_id: 'C-25844r495531_chk'
  tag severity: 'high'
  tag gid: 'V-224171'
  tag rid: 'SV-224171r508023_rule'
  tag stig_id: 'EP11-00-004810'
  tag gtitle: 'SRG-APP-000178-DB-000083'
  tag fix_id: 'F-25832r495532_fix'
  tag 'documentable'
  tag legacy: ['SV-109473', 'V-100369']
  tag cci: ['CCI-000206']
  tag nist: ['IA-6']
end
