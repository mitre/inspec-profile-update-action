control 'SV-223885' do
  title 'The CA-TSS NEWPHRASE and PPSCHAR Control Options must be properly set.'
  desc 'Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks.

Password complexity is one factor of several that determines how long it takes to crack a password. The more complex the password, the greater the number of possible combinations that need to be tested before the password is compromised.

'
  desc 'check', 'From the ISPF Command Shell enter:
TSS MODIFY STATUS

If the NEWPHRASE Control Option conforms to the following requirements, this is not a finding. 

MA=1-32
MN=1-32
ID
MAX=100
MIN=15-100
MINDAYS=1
NR=0-1
SC=1-32
WARN=1-10

If the PPSCHAR Control Option conform to the allowable list defined in CA Top Secret for z/OS Control Options Guide, this is not a finding.

Note: These characters will be specified at a minimum. "40" represents the blank character. Characters can be identified by their character or hex equivalent.'
  desc 'fix', 'Note: Support of mixed case passwords can only be set when the security file has been copied by TSSXTEND with the option NEWPWBLOCK.

Configure the NEWPHRASE Control Option values to the following requirements:

MA=1-32
MN=1-32
ID
MAX=100
MIN=15-100
MINDAYS=1
NR=0-1
SC=1-32
WARN=1-10

Configure the PPSCHAR Control Option to the allowable list defined in CA Top Secret for z/OS User Guide.

Note: These characters will be specified at a minimum. "40" represents the blank character. Characters can be identified by their character or hex equivalent.

Example:

TSS MODIFY NEWPHRASE(MA=1,MN=1,ID,MAX=100,MIN=15,MINDAYS=1,NR=1,SC=1,WARN=10)
TSS MODIFY PPSCHAR(c,c,c,c,...)

(Use the allowable list defined in CA Top Secret for z/OS Control Options Guide.)'
  impact 0.5
  ref 'DPMS Target IBM zOS TSS'
  tag check_id: 'C-25558r516054_chk'
  tag severity: 'medium'
  tag gid: 'V-223885'
  tag rid: 'SV-223885r877726_rule'
  tag stig_id: 'TSS0-ES-000120'
  tag gtitle: 'SRG-OS-000069-GPOS-00037'
  tag fix_id: 'F-25546r868928_fix'
  tag satisfies: ['SRG-OS-000069-GPOS-00037', 'SRG-OS-000070-GPOS-00038']
  tag 'documentable'
  tag legacy: ['SV-107581', 'V-98477']
  tag cci: ['CCI-000192', 'CCI-000193']
  tag nist: ['IA-5 (1) (a)', 'IA-5 (1) (a)']
end
