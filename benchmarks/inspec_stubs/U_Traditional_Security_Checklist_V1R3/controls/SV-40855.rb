control 'SV-40855' do
  title 'COMSEC Account Management - Equipment and Key Storage'
  desc 'Improper handling and storage of COMSEC material can result in the loss or compromise of classified cryptologic devices or classified key or unclassified COMSEC Controlled Items (CCI).  

REFERENCES: 

DoD 5200.22-M (NISPOM), Chapter 9, Section 4

DoD Manual 5200.01, Volume 1, 24 February 2012, SUBJECT: DoD Information Security Program: Overview, Classification, and Declassification, Enclosure 3, para 12.c.

DoD Manual 5200.01, Volume 3, 24 February 2012, SUBJECT: DoD Information Security Program: Protection of Classified Information:
Paragraph 1.b. (1)
Enclosure 2, para 8. & 12.
Enclosure 3 and Appendix to Encl 3 
Enclosure 4, para 1.a.
Enclosure 7, para 7.b. & c.

NIST Special Publication 800-53 (SP 800-53), Rev 4, Controls: SC-12, SC-13

NSA/CSS Policy Manual 3-16, Sections III, VI, X and XI 

CNSS Policy No. 1, NATIONAL POLICY FOR SAFEGUARDING AND CONTROL OF COMSEC MATERIALS

CNSS Policy No. 10, NATIONAL POLICY GOVERNING USE OF APPROVED SECURITY CONTAINERS IN INFORMATION SECURITY APPLICATIONS

DoD Instruction 8523.01, Communications Security (COMSEC), April 22, 2008'
  desc 'check', 'Ask the COMSEC Custodian, COMSEC Responsible Officer (CRO), Security Manager or ISSM how COMSEC equipment and materials are transported, handled and stored.  Physically check that crypto equipment, keys, and keyed crypto are handled and stored properly. Reviewers must annotate specific types of crypto devices observed in the finding details or comments, (e.g. TACLANE, KIV 7, etc.)'
  desc 'fix', 'COMSEC material must be stored in a GSA approved container such as safe, vault, or secure room IAW (NSA/CSS Policy Manual 3-16, Section XI, paragraph 89). Specific standards are: 
1. Keyed crypto equipment must be housed within a proper GSA safe, vault or secure room. 
2. If crypto equipment is not housed within a proper GSA safe, vault or secure room the Crypto Encryption Key must be removed and stored in a GSA approved safe or in a separate room from the crypto equipment when the equipment is not under the continuous observation and control of a properly cleared person. 
3. Information Processing System (IPS) containers (safes) may be used to securely store and operate keyed equipment. 
4. If unclassified crypto equipment is not operated in a safe, vault or secure room it must minimally be maintained within an approved Secret or higher Controlled Access Area (CAA) and further secured in a locked room (equipment closet) or equipment rack suitable for control of sensitive equipment to ensure only system administrator and COMSEC personnel have access to the equipment. 
5. NOTES: This requirement applies to a tactical environment. Unless under continuous observation and control, Crypto Equipment Key must be removed and maintained separately from the encryption device - unless it is operated in a proper safe, vault or secure room.  Ensure that any COMSEC account, materials or equipment being inspected is used for encryption of DoDIN assets.  COMSEC items not used with DoDIN assets should not be inspected. Specifically, only COMSEC items associated with the CCSDs being inspected are to be included in this check.'
  impact 0.7
  ref 'DPMS Target Traditional Security'
  tag check_id: 'C-39551r14_chk'
  tag severity: 'high'
  tag gid: 'V-30837'
  tag rid: 'SV-40855r3_rule'
  tag stig_id: 'CS-01.01.01'
  tag gtitle: 'COMSEC Account Management - Equipment and Key Storage'
  tag fix_id: 'F-34702r8_fix'
  tag 'documentable'
end
