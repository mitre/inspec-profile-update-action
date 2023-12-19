control 'SV-223511' do
  title 'ACF2 TSO2741 GSO record values must be set to obliterate the logon password on 2741 devices.'
  desc 'To prevent the compromise of authentication information, such as passwords during the authentication process, the feedback from the operating system must not provide any information allowing an unauthorized user to compromise the authentication mechanism.'
  desc 'check', 'From the ISPF Command Shell enter:
ACF <enter>
SET CONTROL(GSO)
LIST TSO2741

If the GSO TSO2741 record values conform to the following requirements, this is not a finding.

BS(16)
LENGTH(8)
M1(X)
M2(N)
M3(Z)
M4(M)
STRING()'
  desc 'fix', 'Define a cross out string used to obliterate the logon password on 2741 devices.

Ensure the GSO TSO2741 record values conform to the following requirements.

BS(16)
LENGTH(8)
M1(X)
M2(N)
M3(Z)
M4(M)
STRING()

Example:
SET C(GSO)
INSERT TSO2741 BS(16) LENGTH(8) M1(X) M2(N) M3(Z) M4(M) STRING()

F ACF2,REFRESH(TSO2741)'
  impact 0.5
  ref 'DPMS Target IBM zOS ACF2'
  tag check_id: 'C-25184r695444_chk'
  tag severity: 'medium'
  tag gid: 'V-223511'
  tag rid: 'SV-223511r695445_rule'
  tag stig_id: 'ACF2-ES-000940'
  tag gtitle: 'SRG-OS-000079-GPOS-00047'
  tag fix_id: 'F-25172r504604_fix'
  tag 'documentable'
  tag legacy: ['SV-106829', 'V-97725']
  tag cci: ['CCI-000206']
  tag nist: ['IA-6']
end
