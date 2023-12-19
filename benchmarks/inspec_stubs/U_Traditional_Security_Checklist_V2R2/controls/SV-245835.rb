control 'SV-245835' do
  title 'Classified Reproduction -  Written Procedures for SIPRNet Connected Classified Multi-Functional Devices (MFD) located in Space Not Approved for Collateral Classified Open Storage. NOTE: This vulnerability concerns only PROCEDURES for the reproduction (printing, copying, scanning, faxing) of classified documents on Multi-Functional Devices (MFD) connected to the DoDIN.'
  desc 'Lack of or improper reproduction procedures for classified material could result in the loss or compromise of classified information.

REFERENCES:

CJCSI 6510.01F, INFORMATION ASSURANCE (IA) AND SUPPORT TO COMPUTER NETWORK DEFENSE (CND), Enclosure C, paragraph 34.

NIST Special Publication 800-53 (SP 800-53), Rev 4, Controls: MP-1, MP-4, PE-1,PE-5.

DoDI 8500.01, SUBJECT: Cybersecurity, March 14, 2014 , Enclosure 3, paragraph 7.

DoD Manual 5200.01, Volume 3, SUBJECT: DoD Information Security Program: Protection of Classified Information: Enclosure 2 paragraphs 14.&15.

DoD 5220.22-M (NISPOM), Incorporating Change 2, 18 May 2016, Chapter 4, paragraph 4-102, and Chapter 5, Section 6 (Reproduction).'
  desc 'check', "Classified Reproduction - Document Copying using Multi-Functional Device (MFD) machines (i.e., printer, copier, fax, scanner) connected to SIPRNet. This Check concerns ONLY PROCEDURES for the reproduction of classified DOCUMENTS on Multi-Functional Devices (MFD) connected to the DoDIN.

General guidance: Paper copies, electronic files, and other material containing classified information shall be reproduced only when necessary for accomplishing the organization's mission or for complying with applicable statutes or Directives.  Personnel reproducing classified information must be knowledgeable of the procedures for classified reproduction and aware of the risks involved with the specific reproduction equipment being used and the appropriate countermeasures they are required to take.  Reproduced material is to be placed under the same accountability and control requirements as applied to the original material.     

Classified material is to be reproduced only on approved and, when applicable, properly accredited systems. 

Check to ensure:
  
Check #1. Procedures for the proper reproduction of classified documents are posted on or near the MFD approved for classified reproduction. This is especially true when the MFD is capable of directly making copies of documents on the machine. The procedures must alert users when the particular MFD is approved for classified reproduction.
  
Check #2. Other MFD (used as copiers) in the organization that are not approved for classified document reproduction must also be marked to alert users of the prohibition against making classified copies. 
  
Check #3. Procedures posted near the MFD must contain steps for users to take after printing, copying, scanning or faxing classified documents. Steps must include double checking of the MFD for missed pages, counting original and copied pages, purging or clearing of images from the MFD (if applicable), use of cover sheets, and general protection/control guidelines for reproduced documents. 

NOTE:  Most MFD contain both hard drives (non-volatile memory) and volatile memory and cannot be properly sanitized of classified data or images to make the MFD unclassified. Therefore, most (if not all) classified MFD should be housed and operated within space approved for collateral classified open storage.  If not maintained in spaces approved for classified open storage all MFD with non-volatile memory that is used for classified reproduction must be under the continuous observation and control of a cleared person AT ALL TIMES. A violation of this is a Category 1 Severity level finding and is covered under  STIG ID: IS-10.01.01.
                  
TACTICAL ENVIRONMENT:  This check is applicable in a fixed operational facility in a tactical environment if classified equipment is used or documents or media are created/extracted from the SIPRNet. The only exception will be for urgent (short term) tactical operations or other contingency situations where fixed facilities and equipment are not yet present or incapable of being used."
  desc 'fix', "Classified Reproduction - Document Copying using Multi-Functional Device (MFD) machines (ie., printer, copier, fax, scanner) connected to SIPRNet.  This STIG Check concerns ONLY PROCEDURES for the reproduction of classified DOCUMENTS on Multi-Functional Devices (MFD) connected to the DoDIN.

General guidance: Paper copies, electronic files, and other material containing classified information shall be reproduced only when necessary for accomplishing the organization's mission or for complying with applicable statutes or Directives.  Personnel reproducing classified information must be knowledgeable of the procedures for classified reproduction and aware of the risks involved with the specific reproduction equipment being used and the appropriate countermeasures they are required to take.   Reproduced material is to be placed under the same accountability and control requirements as applied to the original material.     

Classified material is to be reproduced only on approved and, when applicable, properly accredited systems. 

Ensure:
  
1. Procedures for the proper reproduction of classified documents are posted on or near the MFD approved for classified reproduction.  This is especially true when the MFD is capable of directly making copies of documents on the machine. The procedures must alert users when the particular MFD is approved for classified reproduction.
  
2. Other MFD (used as copiers) in the organization that are not approved for classified document reproduction must also be marked to alert users of the prohibition against making classified copies. 
  
3. Procedures posted near the MFD must contain steps for users to take after printing, copying, scanning or faxing classified documents.  Steps must include double checking of the MFD for missed pages, counting original and copied pages, purging of images (if applicable), use of cover sheets, and general protection/control guidelines for reproduced documents. 

NOTE:  Most MFD contain both hard drives (non-volatile memory) and volatile memory and cannot be properly sanitized of classified data or images to make the MFD unclassified.  Therefore, most (if not all) classified MFD should be housed and operated within space approved for collateral classified open storage.  If not maintained in spaces approved for classified open storage all MFD with non-volatile memory  that is used for classified reproduction must be under the continuous observation and control of a cleared person AT ALL TIMES."
  impact 0.3
  ref 'DPMS Target Traditional Security Checklist'
  tag check_id: 'C-49266r822895_chk'
  tag severity: 'low'
  tag gid: 'V-245835'
  tag rid: 'SV-245835r822896_rule'
  tag stig_id: 'IS-10.03.01'
  tag gtitle: 'IS-10.03.01'
  tag fix_id: 'F-49221r770166_fix'
  tag 'documentable'
  tag legacy: ['V-31995', 'SV-42294r3_rule']
end
