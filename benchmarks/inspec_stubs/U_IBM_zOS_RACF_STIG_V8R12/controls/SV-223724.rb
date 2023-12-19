control 'SV-223724' do
  title 'IBM RACF PASSWORD(RULEn) SETROPTS value(s) must be properly set.'
  desc 'The shorter the password, the lower the number of possible combinations that need to be tested before the password is compromised.

Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. Password length is one factor of several that helps to determine strength and how long it takes to crack a password. Use of more characters in a password helps to exponentially increase the time and/or resources required to compromise the password.

'
  desc 'check', 'From the ISPF Command Shell enter:
SETRopts

If the following options are specified, this is not a finding.

At least one PASSWORD(RULE) under "INSTALLATION PASSWORD SYNTAX RULES" is defined with the values shown below:

RULE 1 LENGTH(8) xxxxxxxx

The following options are in effect under "PASSWORD PROCESSING OPTIONS":

"MIXED CASE PASSWORD SUPPORT IS IN EFFECT"
"SPECIAL CHARACTERS ARE ALLOWED."'
  desc 'fix', 'Evaluate the impact associated with implementation of the control option. Develop a plan of action to implement the control option as specified in the example below:

For z/OS release 1.13 and 1.14 PTF UA90720 must be applied.
For z/OS Release 2.1 PTF UA90721 must be applied.

The RACF Command SETR LIST will show the status of RACF Controls including PASSWORD SYNTAX RULEs.

Setting the password syntax to all Mixed Case Alphanumeric and Special Characters is activated with the commands:

setr password(mixedcase)
setr password(specialchars)
setr password(rule1(length(8) mixedall(1:8))'
  impact 0.5
  ref 'DPMS Target IBM zOS RACF'
  tag check_id: 'C-25397r868817_chk'
  tag severity: 'medium'
  tag gid: 'V-223724'
  tag rid: 'SV-223724r868818_rule'
  tag stig_id: 'RACF-ES-000770'
  tag gtitle: 'SRG-OS-000069-GPOS-00037'
  tag fix_id: 'F-25385r516749_fix'
  tag satisfies: ['SRG-OS-000069-GPOS-00037', 'SRG-OS-000078-GPOS-00046']
  tag 'documentable'
  tag legacy: ['V-98155', 'SV-107259']
  tag cci: ['CCI-000192', 'CCI-000205']
  tag nist: ['IA-5 (1) (a)', 'IA-5 (1) (a)']
end
