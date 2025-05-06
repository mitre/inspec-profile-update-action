control 'SV-40975' do
  title 'COMSEC Training - COMSEC User'
  desc 'Failure to properly brief COMSEC users could result in the loss of cryptologic devices or key, or the compromise of classified information.

REFERENCES: 

DoD Manual 5200.01, Volume 1, 24 February 2012, SUBJECT: DoD Information Security Program: Overview, Classification, and Declassification

DoD 5200.22-M (NISPOM), Section 4

DoD Manual 5200.01, Volume 3, 24 February 2012, SUBJECT: DoD Information Security Program: Protection of Classified Information, Encl 7, Para 7.b.

NIST Special Publication 800-53 (SP 800-53), Rev 4, Controls:  AT-3, AT-4, and SC-1

NSA/CSS Policy Manual 3-16, Section IX, Paragraph 77.

CNSS Policy No. 1, NATIONAL POLICY FOR SAFEGUARDING AND CONTROL OF COMSEC MATERIALS

DoD Instruction 8523.01, Communications Security (COMSEC), April 22, 2008

CJCSI 6510.01F, INFORMATION ASSURANCE (IA) AND SUPPORT TO COMPUTER NETWORK DEFENSE (CND)'
  desc 'check', 'Check proof of user training.   

NOTES:

1. Applies in a tactical environment if the crypto equipment and key material being observed is at a location where supporting staff (IAM, SM, COMSEC Custodian/COMSEC Responsible Officer (CRO) AKA: Hand Receipt Holder) would logically be located. If it is a mobile tactical organization, COMSEC users should previously have received proper training; however, since the documentation will likely not be available in a field environment this check will be NA.  

2. Observations and comments may be entered for the record, even if there is no finding.  

3. Ensure that any COMSEC account, materials or equipment being inspected is used for encryption of DoDIN assets. COMSEC accounts or items not used with DoDIN assets should not be inspected.'
  desc 'fix', 'Train all COMSEC users on proper procedures for operation of COMSEC equipment and on proper protection of both classified COMSEC materials as well as COMSEC Controlled Information (CCI). Documented proof of initial user training must be on-hand and updated at least annually.'
  impact 0.5
  ref 'DPMS Target Traditional Security'
  tag check_id: 'C-39594r11_chk'
  tag severity: 'medium'
  tag gid: 'V-30933'
  tag rid: 'SV-40975r3_rule'
  tag stig_id: 'CS-02.02.02'
  tag gtitle: 'COMSEC Training - COMSEC User'
  tag fix_id: 'F-34744r10_fix'
  tag 'documentable'
end
