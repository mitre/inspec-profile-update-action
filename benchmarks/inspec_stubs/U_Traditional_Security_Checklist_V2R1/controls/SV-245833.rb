control 'SV-245833' do
  title 'Classified Reproduction - SIPRNet Connected Classified Multi-Functional Devices (MFD) located in Space Not Approved for Collateral Classified Open Storage.'
  desc 'Classified Multi-Functional Devices (MFD) include printers, copiers, scanners and facsimile capabilities and contain hard drives that maintain classified data or images.  Failure to locate these devices in spaces approved for classified open storage could enable uncleared persons to access classified information, either from unsanitized hard drives or from printed/copied material that is left unattended on the machine for any period of time.

REFERENCES:

CJCSI 6510.01F, INFORMATION ASSURANCE (IA) AND SUPPORT TO COMPUTER NETWORK DEFENSE (CND), Enclosure C, paragraph 34.

NIST Special Publication 800-53 (SP 800-53), Rev 4, Controls: MP-1, MP-4, PE-1, PE-5.

DoDI 8500.01, SUBJECT: Cybersecurity, March 14, 2014 , Enclosure 3, paragraph 7.

DoD Manual 5200.01, Volume 3, SUBJECT: DoD Information Security Program: Protection of Classified Information: Enclosure 2 paragraph 14.&15., Enclosure 3 and Enclosure 7, paragraph 6.

DoD 5200.22-M (NISPOM), Incorporating Change 2, 18 May 2016, paragraphs 8-202.e. & 8-302.b.

NIST Special Publication 800-88, Revision 1, Guidelines for Media Sanitization, December 2014

NSA/CSS Policy Manual 9-12, 15 December 2014, Subject:  NSA/CSS Storage Device Sanitization Manual'
  desc 'check', 'This set of checks covers multi-functional devices (MFD) (connected to the SIPRNet) that are used for printing, copying or other reproduction of classified DOCUMENTS.  

Checks: 
 
1.  Unless the MFD can be properly purged and sanitized (made unclassified) of all classified data or images after each use for classified - it must be housed in an area approved for open storage of classified material.  

Most current copiers, printers, scanners and facsimile machines or multi-functional devices (MFD) contain hard drives that collect and store images and data.  

Therefore check to ensure that such machines are maintained in space approved for open storage of classified (secret or higher for SIPRNet).  

NOTE that to be properly sanitized means that the MFD can be treated as an unclassified piece of equipment once a successful purge of data or images is completed. (CAT I) 

2.  If not maintained within a secret or higher collateral classified open storage area:  

Check that MFD (or individual copiers, scanners, printers or facsimile machines) do not have hard drives containing non-volatile memory in the device and that the volatile memory is purged/sanitized of all classified data or images after each use.

Additionally check that these MFD are maintained in space where access is controlled to at least the level of the classified material authorized to be copied on the machine. This type of area is referred to as a Controlled Access Area (CAA) - at least a secret CAA or TS CAA for SIPRNet connections.
  
ONLY those MFD with entirely volatile memory can be sanitized and reused upon removal of power from the device.  

Check to ensure that powering down the machine is a part of the MFD sanitization procedure to ensure that volatile memory is totally erased and sanitized so that it can be considered to be an unclassified device.  Documented procedures must be on-hand for this process.
 
NOTE:  Sanitizing a MFD means it can be considered and treated as an unclassified device.  Hard drives with non-volatile memory cannot be sanitized by current overwriting/clearing procedures and must be destroyed (degaussing and/or physical destruction) to be considered sanitized/unclassified.  Hence MFD with non-volatile memory cannot be sanitized for reuse.  Only MFD with volatile memory can be sanitized for reuse.  

Only if ALL of the sub-checks listed under check 2 are compliant is it a CAT II finding.  Otherwise if ANY of the sub-checks are not compliant it remains a CAT I finding. (CAT II)

3.  If not maintained within a secret or higher collateral classified open storage area and hard drives with non-volatile memory are present: 

Check to ensure MFD (or individual copiers, scanners, printers or facsimile machines) are located in a secret or higher CAA and the hard drive is promptly removed after each use and stored in a GSA approved safe.  

Check to ensure that powering down the machine is a required part of this procedure to ensure that volatile memory is totally erased and sanitized so that it can be considered to be an unclassified device.   

Check that documented procedures are on hand to support this process. 

Only if ALL of the sub-checks listed under check 3 are compliant is it a CAT II finding.  Otherwise if ANY of the sub-checks are not compliant it remains a CAT I finding. 
(CAT II)

EXPLANATION for CAT II FINDINGS:  Despite the mitigations in checks 2 and 3 above, there is still a concern that the mitigation procedure will not be accomplished promptly or successfully each time and there is a risk for printed or copied classified documents to be left unattended for periods of time in the networked MFD machines, especially when printed from a remote workstation location.  Therefore, since a potential vulnerability still exists it is still considered as a CAT II finding.

TACTICAL ENVIRONMENT:  This check is applicable in a fixed operational facility in a tactical environment if classified equipment is used or documents or media are created/extracted from the SIPRNet.  The only exception will be for urgent (short term) tactical operations or other contingency situations where fixed facilities and equipment are not yet present or incapable of being used.'
  desc 'fix', 'This Potential Vulnerability covers multi-functional devices (MFD) (connected to the SIPRNet) that are used for printing, copying or other reproduction of classified DOCUMENTS.  
 
1.  Unless the MFD can be properly purged of all classified data or images after each use for classified - it must be housed in an area approved for open storage of classified material.  Most current copiers, printers, scanners and facsimile machines or multi-functional devices (MFD) contain hard drives that collect and store images and data.  

Therefore these machines must be maintained in space approved for open storage of classified (secret or higher for SIPRNet).    

NOTE:  Clearing of hard drives (such as by overwriting) is not adequate to sanitize a classified hard drive (magnetic or solid state) so that it can be deemed unclassified and left unattended in an area not approved for classified open storage.  This is regardless of the number of times the drive is over-written.  A hard drive (magnetic or solid state) can only be sanitized (made unclassified) by degaussing and/or physical destruction, thereby rending the drive no longer usable.  
 
2. If not maintained within a secret or higher collateral classified open storage area and hard drives (non-volatile memory) ARE NOT present:
  
MFD (or individual copiers, scanners, printers or facsimile machines) must be properly purged (AKA: sanitized) of classified data or images after each period of reproducing classified and be maintained in space where access is controlled to at least the level of the classified material authorized to be copied on the machine.  This type of area is referred to as a Controlled Access Area (CAA) - at least a secret CAA or TS CAA for SIPRNet connections.  
Sanitizing a MFD means it can be considered and treated as an unclassified device.
  
NOTE:  Hard drives with non-volatile memory cannot be sanitized by current overwriting/clearing procedures and must be destroyed to be considered sanitized/unclassified.  Hence MFD with non-volatile memory cannot be sanitized for reuse.
  
Only those MFD with entirely volatile memory can be sanitized and reused with removal of power from the device.  It is important to note that powering down the machine will be a necessary part of this procedure to ensure that volatile memory is totally erased and sanitized so that it can be considered to be an unclassified device.  Documented procedures must be on-hand for this process.

3.  If not maintained within a secret or higher collateral classified open storage area and hard drives (non-volatile memory) ARE present:
 
MFD (or individual copiers, scanners, printers or facsimile machines) with hard drives (non-volatile memory) must be located and operated in a secret or higher CAA and the hard drive must be promptly removed after each use (or otherwise when unattended by cleared employees) and stored in a GSA approved safe. 
 
It is important to note that powering down the machine will still be a necessary part of this procedure to ensure that volatile memory is totally erased and sanitized so that it can be considered to be an unclassified device. There must be documented procedures on-hand for this process. 

NOTE:  Despite the mitigations in 2 and 3 above, there is still a concern that the procedure will not be accomplished promptly or successfully each time and that the risk for printed or copied classified documents to be left unattended for periods of time in the MFD machines still exists.  Therefore vulnerability still exists and must be considered as a potential finding.'
  impact 0.7
  ref 'DPMS Target Traditional Security Checklist'
  tag check_id: 'C-49264r770159_chk'
  tag severity: 'high'
  tag gid: 'V-245833'
  tag rid: 'SV-245833r770334_rule'
  tag stig_id: 'IS-10.01.01'
  tag gtitle: 'IS-10.01.01'
  tag fix_id: 'F-49219r770160_fix'
  tag 'documentable'
  tag legacy: ['SV-42324r3_rule', 'V-32008']
end
