control 'SV-223892' do
  title 'The IBM z/OS operating system must enforce a minimum eight-character password length.'
  desc 'The shorter the password, the lower the number of possible combinations that need to be tested before the password is compromised.

Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. Password length is one factor of several that helps to determine strength and how long it takes to crack a password. Use of more characters in a password helps to exponentially increase the time and/or resources required to compromise the password.'
  desc 'check', 'From the ISPF Command Shell enter:
TSS MODIFY STATUS

If the NEWPW Control Option values conform to the following requirements, this is not a finding.

NEWPW(MIN=8,WARN=10, MINDAYS=1, NR=0, ID, TS, SC, RS, FA, FN, MC, UC, LC)

NOTE: For the Option SC, the PASSCHAR control option should be set to the allowable list defined in CA Top Secret for z/OS Control Options Guide.

NOTE: For the Option RS, at a minimum use the reserved word prefix list found in the site security plan.'
  desc 'fix', 'Evaluate the impact associated with implementation of the control option. Develop a plan of action to implement the control option setting as specified and proceed with the change.

(Support of mixed case passwords can only be set when the security file has been copied by TSSXTEND with the option NEWPWBLOCK.)

Configure the NEWPW Control Option values to conform to the following requirements:

NEWPW(MIN=8,WARN=10, MINDAYS=1, NR=0, ID, TS, SC, RS, FA, FN, MC, UC, LC)

NOTE: For the Option SC, the PASSCHAR control option should be set to the allowable list defined in CA Top Secret for z/OS Control Options Guide.

NOTE: For the Option RS, at a minimum use the reserved word prefix list found in the site security plan.'
  impact 0.5
  ref 'DPMS Target IBM zOS TSS'
  tag check_id: 'C-25565r516075_chk'
  tag severity: 'medium'
  tag gid: 'V-223892'
  tag rid: 'SV-223892r877733_rule'
  tag stig_id: 'TSS0-ES-000190'
  tag gtitle: 'SRG-OS-000078-GPOS-00046'
  tag fix_id: 'F-25553r516076_fix'
  tag 'documentable'
  tag legacy: ['SV-107595', 'V-98491']
  tag cci: ['CCI-000205']
  tag nist: ['IA-5 (1) (a)']
end
