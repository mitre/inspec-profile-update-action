control 'SV-223509' do
  title 'ACF2 TSOTWX GSO record values must be set to obliterate the logon password on TWX devices.'
  desc 'To prevent the compromise of authentication information, such as passwords during the authentication process, the feedback from the operating system must not provide any information allowing an unauthorized user to compromise the authentication mechanism.

Obfuscation of user-provided information that is typed into the system is a method used when addressing this risk.

Displaying asterisks when a user types in a password is an example of obscuring feedback of authentication information.'
  desc 'check', 'From the ISPF Command Shell enter:
ACF <enter>
SET CONTROL(GSO)
LIST TSOTWX

If the GSO TSOTWX record values conform to the following requirements, this is not a finding.

CR(15)
IDLE(17)
LENGTH(8)
M1(X)
M2(N)
M3(Z)
M4(M)
STRING()'
  desc 'fix', 'Define a cross out mask to obliterate the logon password on TWX devices.

CR(15)
IDLE(17)
LENGTH(8)
M1(X)
M2(N)
M3(Z)
M4(M)
STRING()

Example:
SET C(GSO)
INSERT TSOTWX CR(15) IDLE(17) LENGTH(8) M1(X) M2(N) M3(Z) M4(M) STRING()

F ACF2,REFRESH(TSOTWX)'
  impact 0.5
  ref 'DPMS Target IBM zOS ACF2'
  tag check_id: 'C-25182r695442_chk'
  tag severity: 'medium'
  tag gid: 'V-223509'
  tag rid: 'SV-223509r695443_rule'
  tag stig_id: 'ACF2-ES-000920'
  tag gtitle: 'SRG-OS-000079-GPOS-00047'
  tag fix_id: 'F-25170r500661_fix'
  tag 'documentable'
  tag legacy: ['V-97721', 'SV-106825']
  tag cci: ['CCI-000206']
  tag nist: ['IA-6']
end
