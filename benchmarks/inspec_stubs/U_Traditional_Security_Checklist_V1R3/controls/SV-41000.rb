control 'SV-41000' do
  title 'Protected Distribution System (PDS) Construction - Pull Box Security'
  desc 'A PDS that is not constructed and configured as required could result in the undetected interception of classified information.

REFERENCES: 
                                
CJCSI 6510.01F, INFORMATION ASSURANCE (IA) AND SUPPORT TO COMPUTER NETWORK DEFENSE (CND), Enclosure C, paragraph 35.c.

DoD 5200.22-M (NISPOM), Incorporating Change 2, 18 May 2016 Chapter 5, Section 4, paragraphs 5-402.c. and 5-403
   
DoD Manual 5200.01, Volume 3, 24 February 2012, SUBJECT: DoD Information Security Program: Protection of Classified Information, Encl 4, para 3.b. and 4.a.

NIST Special Publication 800-53 (SP 800-53), Rev 4, Controls:  PE-4, SC-7, and SC-8

CNSSI No. 7003, September 2015, Protected Distribution Systems (PDS), Section VIII, paragraph 25 and Section VI – DEFINITIONS – PDS Lock.'
  desc 'check', 'If pull box covers are capable of being opened and used for accessing the transmission cable, the following 6 checks apply:

Check 1. Box covers do not have removable hinge pins. The hinge must be hidden or mechanically blocked to prevent removal.

Check 2. If the pull box will be accessed after installation, the pull box cover must be secured with an approved PDS lock. Multiple locks may be required for larger pull-boxes. 
 
NOTE 1: The ONLY approved PDS Lock within the DoD is the General Services Administration (GSA) approved changeable combination padlock and has historically been the lock used for securing accessible pull boxes and PDS termination boxes. The only padlock currently meeting this standard is the S&G 8077, changeable combination padlock.

NOTE 2: A newer alternative PDS lock listed by the CNSSI 7003 is the tamper indicative padlock with a wire loop seal. This is a “keyed” padlock with an attached seal that is issued exclusively by the lock proponent, which is the National Security Agency (NSA) Information Assurance Division (IAD) Lock and Seal Office. The USD(I) has determined this lock will not be used for protecting PDS Pull Boxes within the DoD.
  
NOTE 3: The new CNSSI 7003 under the PDS Lock definition identified the wrong federal specification for the changeable combination padlock. The lock identified under FF-L-2740B is designed for safes and will not fit properly on a small PDS lock box. The correct lock (S&G 8077 changeable combination padlock) is under the FF-P-110J federal specification. That is what the CNSSI 7003 proponent "intended" and the DoD TEMPEST Advisory Group (TAG) and NSA Protective Technologies Group are taking action to coordinate correction of this oversight.

Check 3. Hasps (used with PDS locks) to secure the cover on the pull box are permanently and securely attached to the box (e.g., tack welded or with rivets) in such a way as it cannot be removed without breaking the hasp or its connection.
  
Check 4. Ensure boxes with prepunched knockouts are not used.

Check 5. Ensure that for medium threat areas (as defined in the CNSSI 7003), pull boxes are constructed of a ferrous metal with a minimum thickness of 14 gauge and must have a cover that can be locked. However, the material need not be thicker than the PDS carrier or the thickness needed for box rigidity.

Check 6. Ensure that for low threat areas (as defined in the CNSSI 7003), pull boxes are constructed of a ferrous metal with a minimum thickness of 16 gauge.

If pull box covers are NOT capable of being opened or used for accessing the transmission cable, the following 4 checks apply:
 
Check 7. Ensure covers are secured to the pull boxes by welding or epoxy after installation as follows: 
  - If welded, at least one weld must be applied on each side of the box and cover. 
  - If epoxy is used, it must be applied between all mating surfaces continuously around the cover. 
  - Painted surfaces must be treated to form a mechanically strong epoxy bond.

Check 8. Ensure hinge-pins for pull-box covers are non-removable. The hinge must be hidden or mechanically blocked to prevent removal.
 
Check 9. Boxes with pre-punched knockouts are not used under any circumstances.
 
Check 10. For low threat areas (as defined in the CNSSI 7003), pull boxes are constructed of a ferrous metal with a minimum thickness of 16 gauge.

NOTE: Pull boxes located in medium threat areas must have a lockable cover per the CNSSI 7003 and are therefore addressed in check #5 above under pull box covers capable of being opened and used for accessing the transmission cable.'
  desc 'fix', 'If pull box covers are capable of being opened and used for accessing the transmission cable, the following 6 requirements apply: 

1. Box covers must not have removable hinge pins. The hinge must be hidden or mechanically blocked to prevent removal.
 
2. If the pull box will be accessed after installation, the pull box cover must be secured with an approved PDS lock. Multiple locks may be required for larger pull-boxes.
  
NOTE 1: The ONLY approved PDS Lock within the DoD is the General Services Administration (GSA) approved changeable combination padlock and has historically been the lock used for securing accessible pull boxes and PDS termination boxes. The only padlock currently meeting this standard is the S&G 8077, changeable combination padlock.

NOTE 2: A newer alternative PDS lock listed by the CNSSI 7003 is the tamper indicative padlock with a wire loop seal. This is a “keyed” padlock with an attached seal that is issued exclusively by the lock proponent, which is the National Security Agency (NSA) Information Assurance Division (IAD) Lock and Seal Office.  The USD(I) has determined this lock will not be used for protecting PDS Pull Boxes within the DoD. 
 
NOTE 3: The new CNSSI 7003 under the PDS Lock definition identified the wrong federal specification for the changeable combination padlock.  The lock identified under FF-L-2740B is designed for safes and will not fit properly on a small PDS lock box.  The correct lock (S&G 8077 changeable combination padlock) is under the FF-P-110J federal specification.  That is what the CNSSI 7003 proponent "intended" and the DoD TEMPEST Advisory Group (TAG) and NSA Protective Technologies Group are taking action to coordinate correction of this oversight.

3. Hasps (used with PDS locks) to secure the cover on the pull box must be permanently and securely attached to the box (e.g., tack welded or with rivets) in such a way as it cannot be removed without breaking the hasp or its connection.
  
4. Boxes with prepunched knockouts must not be used.

5. Ensure that for medium threat areas (as defined in the CNSSI 7003), pull boxes are constructed of a ferrous metal with a minimum thickness of 14 gauge and must have a cover that can be locked. However, the material need not be thicker than the PDS carrier or the thickness needed for box rigidity.

6. Ensure that for low threat areas (as defined in the CNSSI 7003), pull boxes are constructed of a ferrous metal with a minimum thickness of 16 gauge.

If pull box covers are NOT capable of being opened or used for accessing the transmission cable, the following 4 requirements apply:
 
7. Covers must be secured to the pull boxes by welding or epoxy after installation as follows: 
  - If welded, at least one weld must be applied on each side of the box and cover. 
  - If epoxy is used, it must be applied between all mating surfaces continuously around the cover. 
  - Painted surfaces must be treated to form a mechanically strong epoxy bond.

8. Hinge-pins for pull-box covers must be non-removable. The hinge must be hidden or mechanically blocked to prevent removal.
 
9. Boxes with pre-punched knockouts must not be used under any circumstances.
 
10. For low threat areas (as defined in the CNSSI 7003), pull boxes are constructed of a ferrous metal with a minimum thickness of 16 gauge.

NOTE: Pull boxes located in medium threat areas must have a lockable cover and are therefore addressed in requirement #5 above under pull box covers capable of being opened and used for accessing the transmission cable.'
  impact 0.7
  ref 'DPMS Target Traditional Security'
  tag check_id: 'C-39618r9_chk'
  tag severity: 'high'
  tag gid: 'V-30958'
  tag rid: 'SV-41000r3_rule'
  tag stig_id: 'CS-04.01.03'
  tag gtitle: 'PDS Construction - Pull Boxes'
  tag fix_id: 'F-34768r10_fix'
  tag 'documentable'
  tag potential_impacts: 'The CNSSI 7003 definition of a PDS Lock includes allowance for use of a Tamper Indicative Padlock with a wire loop seal.  A Tamper Evident Seal is also defined as a possible alternative for use on Pull Boxes.  NOTE: The USD (I) Policy has determined the Tamper Indicative Padlock with a wire loop seal and Tamper Evident Seal ARE NOT permitted for use in the DoD.  Basically this is because neither product was properly vetted and listed by the DoD Lock Program.  ONLY the SG 8077 Changeable Combination Padlock is to be used for securing PDS Pull Boxes protecting SIPRNet within the DoD.'
end
