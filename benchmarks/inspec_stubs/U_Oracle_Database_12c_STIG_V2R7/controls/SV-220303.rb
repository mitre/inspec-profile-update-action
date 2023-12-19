control 'SV-220303' do
  title 'Applications must obscure feedback of authentication information during the authentication process to protect the information from possible exploitation/use by unauthorized individuals.'
  desc 'To prevent the compromise of authentication information, such as passwords, during the authentication process, the feedback from the information system shall not provide any information that would allow an unauthorized user to compromise the authentication mechanism.

Obfuscation of user-provided information when typed into the system is a method used in addressing this risk.

For example, displaying asterisks when a user types in a password, is an example of obscuring feedback of authentication information.

Database applications may allow for entry of the account name and password as a visible parameter of the application execution command. This practice should be prohibited and disabled to prevent shoulder surfing.

This calls for inspection of application source code, which will require collaboration with the application developers. It is recognized that in many cases, the database administrator (DBA) is organizationally separate from the application developers and may have limited, if any, access to source code. Nevertheless, protections of this type are so important to the secure operation of databases that they must not be ignored. At a minimum, the DBA must attempt to obtain assurances from the development organization that this issue has been addressed and must document what has been discovered.'
  desc 'check', 'Interview the DBA to determine if any applications that access the database allow for entry of the account name and password on the command line. If any do, determine whether these applications obfuscate authentication data.  If they do not, this is a finding.'
  desc 'fix', 'Configure or modify applications to prohibit display of passwords in clear text on the command line.'
  impact 0.7
  ref 'DPMS Target Oracle Database 12c'
  tag check_id: 'C-22018r392040_chk'
  tag severity: 'high'
  tag gid: 'V-220303'
  tag rid: 'SV-220303r879615_rule'
  tag stig_id: 'O121-N1-015601'
  tag gtitle: 'SRG-APP-000178-DB-000083'
  tag fix_id: 'F-22010r392041_fix'
  tag 'documentable'
  tag legacy: ['SV-76333', 'V-61843']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
