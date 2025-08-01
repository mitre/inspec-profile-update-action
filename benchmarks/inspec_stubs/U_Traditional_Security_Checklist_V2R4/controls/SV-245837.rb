control 'SV-245837' do
  title 'Classified Material Destruction - Improper Disposal of Automated Information System (AIS) Hard Drives and Storage Media'
  desc 'Failure to properly destroy classified material can lead to the loss or compromise of classified or sensitive information.

REFERENCES:

CJCSI 6510.01F, INFORMATION ASSURANCE (IA) AND SUPPORT TO COMPUTER NETWORK DEFENSE (CND), Enclosure C, paragraphs 21.h.(9); 28; 29b.,d.(1)&(2).h.(1)&(2) and para 34.

NIST Special Publication 800-53 (SP 800-53), Rev 4, Controls: MP-1, MP-6, PE-1.

DODI 8500.01, SUBJECT: Cybersecurity, March 14, 2014, Enclosure 3, paragraph 9.b.(8) & (9) 

DOD Manual 5200.01, Volume 3, SUBJECT: DOD Information Security Program: Protection of Classified Information: Enclosure 2, paragraph 14 & 14(d); Enclosure 3 paragraphs 17, 18, & 19; Enclosure 5, paragraph 3.d.(3); Enclosure 7, paragraph 6.

DOD 5220.22-M (NISPOM), Incorporating Change 2, 18 May 2016, paragraphs 5-704, 5-705, 5-706, 5-707, 5-708, 8-202.e. & 8-302.g.

NIST SP 800-88, Guidelines for Media Sanitization

NSA/CSA Policy Manual 9-12, NSA/CSS Storage Device Declassification Manual

NSA/CSS product lists for sanitization, destroying or disposing of various types of media containing sensitive or classified information:

https://www.nsa.gov/Resources/Media-Destruction-Guidance'
  desc 'check', 'For CLASSIFIED automated information system (AIS) data processing and/or storage equipment such as hard drives and media:

Check to ensure data processing or storage devices are properly sanitized (purged of all classified data so that recovery using known laboratory attack is not possible) in accordance with current NSA guidance before such equipment or media is disposed of or placed in use (and/or stored) in a lower classification environment or an unclassified environment. 

NOTE 1: Clearing procedures using overwrite software is not sufficient to dispose of classified equipment or media (for instance by release to property disposal, vendors, or placement in trash) or to re-use it in an unclassified or lesser classification environment other than its original classification level. Clearing will only enable the equipment or media to be re-used within the original classified environment. 

NOTE 2: NSA guidance can be found in the NSA/CSA Policy Manual 9-12, NSA/CSS Storage Device Declassification Manual. Be certain to also read and apply specific guidance for the DOD from Enclosure 3 and Enclosure 7 of Volume 3 of DOD Manual 5200.01. Important excerpts from this guidance pertaining to disposal of classified equipment and storage media follow:

Classified IT storage media (e.g., hard drives) cannot be declassified by overwriting.

Sanitization (which may destroy the usefulness of the media) or physical destruction is required for disposal.

NOTE 3: The specific methods and procedures for sanitization of classified hard drives or storage media differ depending on sensitivity of data, type of hard drive or storage media (magnetic, solid state, etc...) and ownership of the hard drive or storage media. To ensure DOD information is not inadvertently disclosed to unauthorized individuals, the activity security manager should coordinate with the local Authorizing Official (AO) and/or IT staff to ensure local procedures for disposal of computer hard drives appropriately address removal of U.S. Government data prior to disposal.

TACTICAL ENVIRONMENT: Applies in all environments whenever classified documents or materials are to be destroyed.'
  desc 'fix', 'For CLASSIFIED automated information system (AIS) data processing and/or storage equipment such as hard drives and media:

CLASSIFIED automated information system (AIS) data processing/storage devices such as system hard drives and media must be properly sanitized using approved NSA guidelines (purged of all classified data so that recovery using known laboratory attack is not possible) before such equipment or media is disposed of or placed in use (and/or stored) in a lower classification environment or an unclassified environment. 

NOTE 1: Clearing procedures using overwrite software is not sufficient to dispose of classified equipment or media (for instance by release to property disposal, vendors, or placement in trash) or to re-use it in an unclassified or lesser classification environment other than its original classification level. Clearing will only enable the equipment or media to be re-used within the original classified environment. 

NOTE 2: NSA guidance for classified equipment can be found in the NSA/CSA Policy Manual 9-12, NSA/CSS Storage Device Declassification Manual. Sanitization and disposal must also be IAW Enclosure 3 and Enclosure 7 of Volume 3 of DOD Manual 5200.01, which provides additional clarifying guidance for the DOD. Some important excerpts from this guidance pertaining to classified equipment and storage media follows:
Classified IT storage media (e.g., hard drives) cannot be declassified by overwriting.
Sanitization (which may destroy the usefulness of the media) or physical destruction is required for disposal.

NOTE 3: The specific methods and procedures for sanitization of classified hard drives or storage media differ depending on sensitivity of data, type of hard drive or storage media (magnetic, solid state, etc...) and ownership of the hard drive or storage media. To ensure DOD information is not inadvertently disclosed to unauthorized individuals, the activity security manager should coordinate with the local Authorizing Official (AO) and/or IT staff to ensure local procedures for disposal of computer hard drives appropriately address removal of U.S. Government data prior to disposal.'
  impact 0.7
  ref 'DPMS Target Traditional Security Checklist'
  tag check_id: 'C-49268r917235_chk'
  tag severity: 'high'
  tag gid: 'V-245837'
  tag rid: 'SV-245837r917350_rule'
  tag stig_id: 'IS-11.01.02'
  tag gtitle: 'IS-11.01.02'
  tag fix_id: 'F-49223r917236_fix'
  tag 'documentable'
  tag legacy: ['V-32111', 'SV-42428r3_rule']
end
