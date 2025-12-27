control 'SV-42295' do
  title 'Classified Reproduction - Following guidance for System to Media Transfer of Data from systems connected specifically to the SIPRNet In-Accordance-With (IAW) US CYBERCOM CTO 10-133A .'
  desc 'Failure to follow guidance for disabling removable media drives on devices connected to the SIPRNet or if approved by the local DAA failure to  follow US CYBERCOM procedures for using removable media on SIPRNet could result in the loss or compromise of classified information.

REFERENCES:

USCYBERCOM Communications Tasking Order (CTO) 10-133

CTO 10-004A; CTO 09-002; CTO 10-084A & CTO 10-133A 

CJCSI 6510.01F, INFORMATION ASSURANCE (IA) AND SUPPORT TO COMPUTER NETWORK DEFENSE (CND), Enclosure A, paragraph 6 and Enclosure C, paragraph 21.h.

NIST Special Publication 800-53 (SP 800-53), Rev 4, Controls: MP-2, MP-4, SI-12.

DoDI 8500.01, SUBJECT: Cybersecurity, March 14, 2014 , Enclosure 3, paragraph 7.

DoD Manual 5200.01, Volume 3, SUBJECT: DoD Information Security Program: Protection of Classified Information: Enclosure 2 paragraph 15., Enclosure 3 and Enclosure 7.

DoD 5200.22-M (NISPOM), Incorporating Change 2, 18 May 2016, Chapter 8.

NIST Special Publication 800-88, Revision 1, Guidelines for Media Sanitization, December 2014

NSA/CSS Policy Manual 9-12, 15 December 2014, Subject:  NSA/CSS Storage Device Sanitization Manual

CNSSP 26, National Policy on Reducing the Risk of Removable Media'
  desc 'check', 'General guidance: Paper copies, electronic files, and other material containing classified information shall be reproduced only when necessary for accomplishing the organizations mission or for complying with applicable statutes or Directives.  Personnel reproducing classified information must be knowledgeable of the procedures for classified reproduction and aware of the risks involved with the specific reproduction equipment and media being used and the appropriate countermeasures they are required to take.  Reproduced material is to be placed under the same accountability and control requirements as applied to the original material. Classified material is to be reproduced only on approved and when applicable, properly
accredited systems. 

This check concerns ONLY reproduction and/or transfer of classified data using all forms of removable media on SIPRNet connected devices or systems.  

Check to ensure that US CYBERCOM Communications Tasking Order (CTO) 10-133A is being complied with as follows:  

1.  Ensure that the write capability for all possible removable media is disabled as a default setting on all SIPRNet connected machines.  

2. Ensure that write settings are only allowed when specifically approved by using the HBSS Device Control Module (DCM).  

3. Ensure the system AO has specifically approved all persons authorized to transfer data from SIPRNet connected system components.  

4. Ensure the ISSM maintains a list of all persons authorized by the AO to transfer data from the SIPRNet.  

5. Ensure there are written procedures approved by the AO for use of removable media on SIPRNet.  

NOTE:  Coordination with Technical Reviewers may be required to determine all of the information outlined above.
                                        
TACTICAL ENVIRONMENT:  This check is applicable in a fixed operational facility in a tactical environment if classified equipment is used or documents or media are created/extracted from the SIPRNet.  The only exception will be for urgent (short term) tactical operations or other contingency situations where fixed facilities and equipment are not yet present or incapable of being used.'
  desc 'fix', 'General guidance to consider: Paper copies, electronic files, and other material containing classified information shall be reproduced only when necessary for accomplishing the organizations mission or for complying with applicable statutes or Directives.  Personnel reproducing classified information must be knowledgeable of the procedures for classified reproduction and aware of the risks involved with the specific reproduction equipment and media being used and the appropriate countermeasures they are required to take.  Reproduced material is to be placed under the same accountability and control requirements as applied to the original material. Classified material is to be reproduced only on approved and when applicable, properly
accredited systems. 

This check concerns ONLY reproduction and/or transfer of classified data using all forms of removable media on SIPRNet connected devices or systems.  

Ensure that US CYBERCOM Communications Tasking Order (CTO) 10-133A is being complied with as follows:  

1.  Ensure that the write capability for all possible removable media is disabled as a default setting on all SIPRNet connected machines.  

2. Ensure that write settings are only allowed when specifically approved by using the HBSS Device Control Module (DCM).  

3. Ensure the system AO has specifically approved all persons authorized to transfer data from SIPRNet connected system components.  

4. Ensure the ISSM maintains a list of all persons authorized by the AO to transfer data from the SIPRNet.  

5. Ensure there are written procedures approved by the AO for use of removable media on SIPRNet.'
  impact 0.5
  ref 'DPMS Target Traditional Security'
  tag check_id: 'C-40636r9_chk'
  tag severity: 'medium'
  tag gid: 'V-31996'
  tag rid: 'SV-42295r3_rule'
  tag stig_id: 'IS-10.02.01'
  tag gtitle: 'Classified Reproduction - System to Media Transfer from SIPRNet IAW  US CYBERCOM CTO 10-133A'
  tag fix_id: 'F-35930r5_fix'
  tag 'documentable'
end
