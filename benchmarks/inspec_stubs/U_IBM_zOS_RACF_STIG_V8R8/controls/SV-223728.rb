control 'SV-223728' do
  title 'The IBM RACF PASSWORD(HISTORY) SETROPTS value must be set to 5 or more.'
  desc 'Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. HISTORY specifies the number of previous passwords that RACF saves for each USERID and compares with an intended new password. If there is a match with one of the previous passwords, or with the current password, RACF rejects the intended new password.'
  desc 'check', 'From the ISPF Command Shell enter:
SETRopts List

If the PASSWORD(HISTORY) value is set properly then the message x GENERATIONS OF PREVIOUS PASSWORDS BEING MAINTAINED, where x is a minimum of "5", this is not a finding.'
  desc 'fix', 'Configure the PASSWORD(HISTORY) SETROPTS value is set to a minimum of "5". This specifies the number of previous passwords that RACF saves for each USERID and compares with an intended new password. If there is a match with one of the previous passwords, or with the current password, RACF rejects the intended new password.

Evaluate the impact associated with implementation of the control option. Develop a plan of action to implement the control option as specified in the example below:

The RACF Command SETR LIST will show the status of RACF Controls including PASSWORD HISTORY. 

Setting the password history to 10 generations is activated with the command SETR PASSWORD(HISTORY(10)).'
  impact 0.5
  ref 'DPMS Target IBM zOS RACF'
  tag check_id: 'C-25401r571994_chk'
  tag severity: 'medium'
  tag gid: 'V-223728'
  tag rid: 'SV-223728r604139_rule'
  tag stig_id: 'RACF-ES-000810'
  tag gtitle: 'SRG-OS-000077-GPOS-00045'
  tag fix_id: 'F-25389r571995_fix'
  tag 'documentable'
  tag legacy: ['SV-107267', 'V-98163']
  tag cci: ['CCI-000200']
  tag nist: ['IA-5 (1) (e)']
end
