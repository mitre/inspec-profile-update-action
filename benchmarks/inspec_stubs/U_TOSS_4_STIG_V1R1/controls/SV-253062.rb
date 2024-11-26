control 'SV-253062' do
  title 'TOSS must enforce password complexity by requiring that at least one numeric character be used.'
  desc 'Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks.

Password complexity is one factor of several that determines how long it takes to crack a password. The more complex the password, the greater the number of possible combinations that need to be tested before the password is compromised.

TOSS utilizes "pwquality" as a mechanism to enforce password complexity. Note that in order to require numeric characters, without degrading the minlen value, the credit value must be expressed as a negative number in "/etc/security/pwquality.conf."'
  desc 'check', 'Verify the value for "dcredit" in "/etc/security/pwquality.conf" with the following command:

$ sudo grep dcredit /etc/security/pwquality.conf 
dcredit = -1 

If the value of "dcredit" is a positive number or is commented out, this is a finding.'
  desc 'fix', 'Configure the operating system to enforce password complexity by requiring that at least one numeric character be used by setting the "dcredit" option.

Add the following line to /etc/security/pwquality.conf (or modify the line to have the required value):

dcredit = -1'
  impact 0.5
  ref 'DPMS Target TOSS 4'
  tag check_id: 'C-56515r824856_chk'
  tag severity: 'medium'
  tag gid: 'V-253062'
  tag rid: 'SV-253062r824858_rule'
  tag stig_id: 'TOSS-04-040070'
  tag gtitle: 'SRG-OS-000071-GPOS-00039'
  tag fix_id: 'F-56465r824857_fix'
  tag 'documentable'
  tag cci: ['CCI-000194']
  tag nist: ['IA-5 (1) (a)']
end
