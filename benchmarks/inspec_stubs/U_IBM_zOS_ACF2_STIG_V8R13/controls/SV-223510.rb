control 'SV-223510' do
  title 'ACF2 TSOCRT GSO record values must be set to obliterate the logon to ASCII CRT devices.'
  desc 'To prevent the compromise of authentication information, such as passwords during the authentication process, the feedback from the operating system must not provide any information allowing an unauthorized user to compromise the authentication mechanism.

Obfuscation of user-provided information that is typed into the system is a method used when addressing this risk.

Displaying asterisks when a user types in a password is an example of obscuring feedback of authentication information.'
  desc 'check', 'From the ISPF Command Shell enter:
ACF
SET CONTROL(GSO) <enter>
LIST TSOCRT

If the GSO TSOCRT record values conform to the following requirements, this is not a finding.

STRING(A12FA11C1A270C0D)'
  desc 'fix', 'Define a clear string used to obliterate the logon to ASCII CRT devices.

STRING(A12FA11C1A270C0D)

Example:
SET C(GSO)
INSERT TSOCRT STRING(A12FA11C1A270C0D)

F ACF2,REFRESH(TSOCRT)'
  impact 0.5
  ref 'DPMS Target IBM zOS ACF2'
  tag check_id: 'C-25183r500663_chk'
  tag severity: 'medium'
  tag gid: 'V-223510'
  tag rid: 'SV-223510r533198_rule'
  tag stig_id: 'ACF2-ES-000930'
  tag gtitle: 'SRG-OS-000079-GPOS-00047'
  tag fix_id: 'F-25171r500664_fix'
  tag 'documentable'
  tag legacy: ['V-97723', 'SV-106827']
  tag cci: ['CCI-000206']
  tag nist: ['IA-6']
end
