control 'SV-223886' do
  title 'The CA-TSS NEWPW control options must be properly set.'
  desc 'If the private key is stolen, this will lead to the compromise of the authentication and non-repudiation gained through PKI because the attacker can use the private key to digitally sign documents and pretend to be the authorized user.

'
  desc 'check', 'From the ISPF Command Shell enter:
TSS MODIFY STATUS

If the NEWPW Control Option values conform to the following requirements, this is not a finding.

NEWPW(MIN=8,WARN=10, MINDAYS=1, NR=0, ID, TS, SC, RS, FA, FN, MC, UC, LC)

NOTE: For the Option SC, the PASSCHAR control option should be set to the allowable list defined in CA Top Secret for z/OS Control Options Guide.

NOTE: For the Option RS, at a minimum use the reserved word prefix list found in the site security plan.'
  desc 'fix', 'Note: Support of mixed case passwords can only be set when the security file has been copied by TSSXTEND with the option NEWPWBLOCK.

Configure the NEWPW Control Option values conform to the following requirements:

NEWPW(MIN=8,WARN=10, MINDAYS=1, NR=0, ID, TS, SC, RS, FA, FN, MC, UC, LC)

NOTE: For the Option SC, the PASSCHAR control option should be set to the allowable list defined in CA Top Secret for z/OS Control Options Guide.

NOTE: For the Option RS, at a minimum use the reserved word prefix list found in the site security plan.'
  impact 0.5
  ref 'DPMS Target IBM zOS TSS'
  tag check_id: 'C-25559r516057_chk'
  tag severity: 'medium'
  tag gid: 'V-223886'
  tag rid: 'SV-223886r561402_rule'
  tag stig_id: 'TSS0-ES-000130'
  tag gtitle: 'SRG-OS-000071-GPOS-00039'
  tag fix_id: 'F-25547r516058_fix'
  tag satisfies: ['SRG-OS-000071-GPOS-00039', 'SRG-OS-000072-GPOS-00040', 'SRG-OS-000075-GPOS-00043', 'SRG-OS-000480-GPOS-00225', 'SRG-OS-000266-GPOS-00101', 'SRG-OS-000279-GPOS-00109']
  tag 'documentable'
  tag legacy: ['V-98479', 'SV-107583']
  tag cci: ['CCI-000194', 'CCI-000195', 'CCI-000198', 'CCI-000366', 'CCI-001619', 'CCI-002361']
  tag nist: ['IA-5 (1) (a)', 'IA-5 (1) (b)', 'IA-5 (1) (d)', 'CM-6 b', 'IA-5 (1) (a)', 'AC-12']
end
