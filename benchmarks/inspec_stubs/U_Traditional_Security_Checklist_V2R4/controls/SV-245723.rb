control 'SV-245723' do
  title 'COMSEC Account Management - Appointment of Responsible Person'
  desc 'Lack of formal designation of an individual to be responsible for COMSEC items could result in mismanagement, loss or even compromise of COMSEC materials.  Additionally, lack of formal vetting for a specific individual to be appointed for management of COMSEC material could result in a person (such as a non-US Citizen) having unauthorized access.

REFERENCES: 

DoD Manual 5200.01, Volume 1, 24 February 2012, SUBJECT: DoD Information Security Program: Overview, Classification, and Declassification, Encl 3, paragraph 6.e. (3).

DoD 5220.22-M (NISPOM), Section 4

DoD Manual 5200.02, Procedures for the DoD Personnel Security Program (PSP), paragraphs 6.5.d., 7.16. e. & f. and 8.2.b. (3)

NIST Special Publication 800-53 (SP 800-53), Rev 4, Controls: IA-1, PL-1, PS-1, PS-2, and SC-1

NSA/CSS Policy Manual 3-16, Sections III, VI, X and XI 

CNSS Policy No.1, NATIONAL POLICY FOR SAFEGUARDING AND CONTROL OF COMSEC MATERIALS'
  desc 'check', 'Check there is a current COMSEC Custodian appointment letter or verify there is a Hand Receipt Holder for COMSEC key material received from a supporting account.  NOTE:  Ensure that any COMSEC account, materials or equipment being inspected is used for encryption of DoDIN assets. COMSEC accounts or items not used with DoDIN assets should not be inspected.'
  desc 'fix', 'A person must be identified and appointed in writing to be either the COMSEC custodian or a COMSEC Hand Receipt Holder. Alternates must also be appointed in writing.'
  impact 0.3
  ref 'DPMS Target Traditional Security Checklist'
  tag check_id: 'C-49154r769829_chk'
  tag severity: 'low'
  tag gid: 'V-245723'
  tag rid: 'SV-245723r822790_rule'
  tag stig_id: 'CS-01.03.01'
  tag gtitle: 'CS-01.03.01'
  tag fix_id: 'F-49109r769830_fix'
  tag 'documentable'
  tag legacy: ['V-30885', 'SV-40925r3_rule']
end
