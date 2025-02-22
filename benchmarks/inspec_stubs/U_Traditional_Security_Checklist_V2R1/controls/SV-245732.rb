control 'SV-245732' do
  title 'Protected Distribution System (PDS) Construction - External Suspended PDS'
  desc 'Suspended carriers (Exterior PDS) are a Category 2 PDS option used to extend a PDS between Controlled Access Areas (CAAs) that are located in different buildings.  Suspended carriers may be used for short runs when it is not practical to bury the PDS between buildings (e.g., between the 3rd floors of adjacent buildings).  Unlike other Category 2 PDS the unencrypted data cables are not required to be installed in a carrier. Proper elevation and ease of visibility as well as minimum daily visual inspections of suspended carriers is of paramount importance.  A PDS that is not configured, physically secured and inspected as required could result in the undetected interception of classified information.  This is especially true for unencrypted cables running through an outdoor environment where physical barriers protecting the environment are often easily breeched.   

REFERENCES: 
                                
CJCSI 6510.01F, INFORMATION ASSURANCE (IA) AND SUPPORT TO COMPUTER NETWORK DEFENSE (CND), Enclosure C, paragraph 35.c.

DoD 5200.22-M (NISPOM), Incorporating Change 2, 18 May 2016 Chapter 5, Section 4, paragraphs 5-402.c. and 5-403   

DoD Manual 5200.01, Volume 3, 24 February 2012, SUBJECT: DoD Information Security Program: Protection of Classified Information, Encl 4, para 3.b. and 4.a.

NIST Special Publication 800-53 (SP 800-53), Rev 4, Controls:  PE-4, SC-7, and SC-8

DoD 5200.22-M (NISPOM), Chapter 5, paragraphs 5-402. (c) and 5-403. (a).

CNSSI No. 7003, September 2015, Protected Distribution Systems (PDS), Section IV, paragraph 7 and Section X, paragraph 30.c.'
  desc 'check', 'Suspended carriers (Exterior PDS) may be used for short runs when it is not practical to bury the PDS between buildings (e.g., between the 3rd floors of adjacent buildings).
 
Check to ensure:

1. Suspended carriers between buildings terminate in a Secret or higher Controlled Access Area (CAA) on each end OR immediately enter a hardened PDS at the building boundary.  (CAT I)

2. Suspended carriers are hung directly between buildings.  (CAT I)

3. Suspended carriers are elevated a minimum of 5 meters (16 feet 4 inches).  (CAT I)

4. Suspended carriers are on property owned or leased by the USG or by a USG contractor or vendor that controls the PDS. (CAT I)

5. Suspended carriers are installed to provide unimpeded visual inspection and be clear of any obstruction or device which encroaches upon the system to facilitate tampering. (CAT I)

6. The areas containing suspended carriers are illuminated at night. (CAT I)

7. The PDS is not located within an Uncontrolled Access Area (UAA).  (CAT I)'
  desc 'fix', 'Suspended carriers may only be used for short runs when it is not practical to bury the PDS between buildings (e.g., between the 3rd floors of adjacent buildings). 
Ensure that:

1. Suspended carriers between buildings are permissible if they terminate in a CAA on each end or immediately enter a hardened PDS at the building boundary. 

2. The suspended carrier must be hung directly between buildings. 

3. The suspended carrier must be elevated a minimum of 5 meters (16 feet 4 inches) and 

4. The suspended carrier must only be used if the property traversed is owned or leased by the USG or by a USG contractor or vendor that controls the PDS. 

5. Suspended carriers must be installed to provide unimpeded inspection and be clear of any obstruction or device which encroaches upon the system to facilitate tampering.
 
6. The area containing the suspended carrier must be illuminated at night.

7. The PDS must not be located within an Uncontrolled Access Area (UAA).'
  impact 0.7
  ref 'DPMS Target Traditional Security Checklist'
  tag check_id: 'C-49163r769856_chk'
  tag severity: 'high'
  tag gid: 'V-245732'
  tag rid: 'SV-245732r769858_rule'
  tag stig_id: 'CS-04.01.05'
  tag gtitle: 'CS-04.01.05'
  tag fix_id: 'F-49118r769857_fix'
  tag 'documentable'
  tag legacy: ['V-30970', 'SV-41012r3_rule']
end
