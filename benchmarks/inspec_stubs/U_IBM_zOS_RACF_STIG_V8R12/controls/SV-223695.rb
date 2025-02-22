control 'SV-223695' do
  title 'The IBM RACF PASSWORD(REVOKE) SETROPTS value must be specified to revoke the userid after three invalid logon attempts.'
  desc 'By limiting the number of failed logon attempts, the risk of unauthorized system access via user password guessing, otherwise known as brute-force attacks, is reduced. Limits are imposed by locking the account.'
  desc 'check', 'From the ISPF Command Shell enter:
SETRopts List

If the PASSWORD(REVOKE) value shows "AFTER <n> CONSECUTIVE UNSUCCESSFUL PASSWORD ATTEMPTS, A USERID WILL BE REVOKED." where <n> is either "1" or "2", this is not a finding.

If the PASSWORD(REVOKE) value is not enabled and is not set to either "1" or "2", this is a finding.'
  desc 'fix', 'Ensure that PASSWORD(REVOKE) SETROPTS value is set to "1" or "2". This specifies the number of consecutive incorrect password attempts RACF allows before it revokes the USERID on the next incorrect attempt. If you specify REVOKE, ensure INITSTATS are in effect.

Evaluate the impact associated with implementation of the control option. Develop a plan of action to implement the control option as specified in the example below:

The RACF Command SETR LIST will show the status of RACF Controls including PASSWORD REVOKE. 

Setting the password REVOKE to "2" invalid attempts activated with the command SETR PASSWORD(REVOKE(2)).'
  impact 0.5
  ref 'DPMS Target IBM zOS RACF'
  tag check_id: 'C-25368r514773_chk'
  tag severity: 'medium'
  tag gid: 'V-223695'
  tag rid: 'SV-223695r604139_rule'
  tag stig_id: 'RACF-ES-000480'
  tag gtitle: 'SRG-OS-000021-GPOS-00005'
  tag fix_id: 'F-25356r514774_fix'
  tag 'documentable'
  tag legacy: ['SV-107201', 'V-98097']
  tag cci: ['CCI-000044']
  tag nist: ['AC-7 a']
end
