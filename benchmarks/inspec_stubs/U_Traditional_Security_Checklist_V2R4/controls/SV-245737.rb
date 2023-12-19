control 'SV-245737' do
  title 'Protected Distribution System (PDS) Construction - Sealed Joints'
  desc 'A PDS that is not constructed and sealed as required could result in the undetected interception of classified information.  Sealing of joints is necessary to ensure that daily visual inspections of the PDS for signs of attempted or actual intrusion can be accurately and thoroughly conducted. 

REFERENCES:
                                 
CJCSI 6510.01F, INFORMATION ASSURANCE (IA) AND SUPPORT TO COMPUTER NETWORK DEFENSE (CND), Enclosure C, paragraph 35.c.

DoD 5220.22-M (NISPOM), Incorporating Change 2, 18 May 2016 Chapter 5, Section 4, paragraphs 5-402.c. and 5-403   

DoD Manual 5200.01, Volume 3, 24 February 2012, SUBJECT: DoD Information Security Program: Protection of Classified Information, Encl 4, para 3.b. and 4.a.

NIST Special Publication 800-53 (SP 800-53), Rev 4, Controls:  PE-4, SC-7, and SC-8

CNSSI No. 7003, September 2015, Protected Distribution Systems (PDS), Section VIII, paragraph 26. and Section X, paragraph 30.a & b.'
  desc 'check', 'Check to ensure:
 
1. All PDS seams and connectors are permanently sealed completely around all surfaces (e.g., welding (continuous or track), epoxy, fusion).
 
2. When a connection consists of more than one seam (e.g., a compression couple), then all seams must be sealed.
 
3. The seal provides a mechanical bond between the components of the carrier and are visible for inspection. 

4. Epoxy seals use a thick, opaque material.
 
5. Couplers that are secured with a "set screw" are not used.

6. If pull boxes are used during installation, check that the pull-box covers are secured/sealed to the pull boxes by welding or epoxy after installation.

7. If welded, at least one weld must be applied on each side of the box and cover.

8. If epoxy is used, it is applied between all mating surfaces continuously around the cover.
 
9. Painted surfaces are treated to form a mechanically strong epoxy bond.

10. Boxes with pre-punched knockouts are not used under any circumstances.

NOTE:  If a pre-fabricated (Modular types such as Holocom or Wiremold) PDS is used it is also required to have all joints sealed as specified above.'
  desc 'fix', '1. All PDS seams and connectors must be permanently sealed completely around all surfaces (e.g., welding (continuous or track), epoxy, fusion). 

2. When a connection consists of more than one seam (e.g., a compression couple), then all seams must be sealed. 

3. The seal must provide a mechanical bond between the components of the carrier and are visible for inspection.
 
4. Epoxy seals must use a thick, opaque material.
 
5. Couplers that are secured with a "set screw" must not be used.

6. If pull boxes are used during installation, the pull-box covers must be secured/sealed to the pull boxes by welding or epoxy after installation.

7. If welded, at least one weld must be applied on each side of the box and cover.

8. If epoxy is used, it must be applied between all mating surfaces continuously around the cover. 

9. Painted surfaces must be treated to form a mechanically strong epoxy bond.

10. Boxes with pre-punched knockouts must not be used under any circumstances.

NOTE:  If a pre-fabricated (Modular types such as Holocom or Wiremold) PDS is used it is also required to have all joints sealed as specified above.'
  impact 0.5
  ref 'DPMS Target Traditional Security Checklist'
  tag check_id: 'C-49168r769871_chk'
  tag severity: 'medium'
  tag gid: 'V-245737'
  tag rid: 'SV-245737r822804_rule'
  tag stig_id: 'CS-04.02.02'
  tag gtitle: 'CS-04.02.02'
  tag fix_id: 'F-49123r769872_fix'
  tag 'documentable'
  tag legacy: ['V-30949', 'SV-40991r4_rule']
end
