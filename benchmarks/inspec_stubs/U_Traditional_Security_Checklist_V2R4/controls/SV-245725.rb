control 'SV-245725' do
  title 'COMSEC Training - COMSEC Custodian or Hand Receipt Holder'
  desc 'Lack of appropriate training for managers of COMSEC accounts could result in the mismanagement of COMSEC records and inadequate physical protection and ultimately lead to the loss or compromise of COMSEC keying material. 

REFERENCES:

DOD Manual 5200.01, Volume 1, 24 February 2012, SUBJECT: DOD Information Security Program: Overview, Classification, and Declassification

DOD 5220.22-M (NISPOM), Section 4

NIST Special Publication 800-53 (SP 800-53), Rev 4, Controls: AT-3, AT-4, and SC-1

NSA/CSS Policy Manual 3-16, Section III, paragraph 16
. 
CNSS Policy No.1, NATIONAL POLICY FOR SAFEGUARDING AND CONTROL OF COMSEC MATERIALS

DOD Instruction 8523.01, Communications Security (COMSEC), January 6, 2021

CJCSI 6510.01F, INFORMATION ASSURANCE (IA) AND SUPPORT TO COMPUTER NETWORK DEFENSE (CND)'
  desc 'check', 'Check for documented proof of COMSEC Custodian or hand receipt holder training.

NOTES:

1. Formal training for primary COMSEC account holders must be completed within six months of being designated as COMSEC Custodian.

2. Ensure that any COMSEC account, materials or equipment being inspected is used for encryption of DODIN assets. COMSEC accounts or items not used with DODIN assets should not be inspected.'
  desc 'fix', 'Documented proof of required COMSEC Custodian or hand receipt holder training must be available. Formal training of primary COMSEC account holders is required within 6-months of being appointed as COMSEC Custodian or alternate. Sub-Account or hand receipt holders may be trained by the sponsoring primary account COMSEC Custodian.'
  impact 0.5
  ref 'DPMS Target Traditional Security Checklist'
  tag check_id: 'C-49156r917142_chk'
  tag severity: 'medium'
  tag gid: 'V-245725'
  tag rid: 'SV-245725r917317_rule'
  tag stig_id: 'CS-02.02.01'
  tag gtitle: 'CS-02.02.01'
  tag fix_id: 'F-49111r917143_fix'
  tag 'documentable'
  tag legacy: ['V-30931', 'SV-40973r3_rule']
end
