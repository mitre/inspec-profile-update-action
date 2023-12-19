control 'SV-245731' do
  title 'Protected Distribution System (PDS) Construction - Buried PDS Carrier'
  desc 'Buried carriers are normally used to extend a PDS between CAAs that are located in different buildings. As with other Category 2 PDS the unencrypted data cables must be installed in a carrier. A PDS that is not constructed, configured and physically secured as required could result in the undetected interception of classified information.  This is especially true for unencrypted cables running through an outdoor environment where physical barriers protecting the environment are often easily breeched.   

REFERENCES:
                                 
CJCSI 6510.01F, INFORMATION ASSURANCE (IA) AND SUPPORT TO COMPUTER NETWORK DEFENSE (CND), Enclosure C, paragraph 35.c.

DoD 5220.22-M (NISPOM), Incorporating Change 2, 18 May 2016 Chapter 5, Section 4, paragraphs 5-402.c. and 5-403 
  
DoD Manual 5200.01, Volume 3, 24 February 2012, SUBJECT: DoD Information Security Program: Protection of Classified Information, Encl 4, para 3.b. and 4.a.

NIST Special Publication 800-53 (SP 800-53), Rev 4, Controls:  PE-4, SC-7, and SC-8

DoD 5220.22-M (NISPOM), Chapter 5, paragraphs 5-402. (c) and 5-403.(a).

CNSSI No. 7003, September 2015, Protected Distribution Systems (PDS), Section IV, paragraph 7 and Section X, paragraph 30.b.'
  desc 'check', "Check Content for exterior PDS.

If the Category 2 hardened carrier is buried:

1. Check to ensure the buried carrier is constructed of conduit consisting of EMT, rigid pipe, PVC, or a similar type of plastic electrical conduit. (CAT I finding)

2. Check that all connections are permanently sealed completely around all mating surfaces (e.g., welding, epoxy, fusion, or PVC glue). (CAT I finding)

3. Check to ensure it is buried a minimum of 1 meter (39 inches) below the surface and on the property (in a LOW Threat area within CONUS) owned or leased by the U.S. Government or the contractor having control of the PDS. NOTE: As an alternative, if the carrier cannot be buried to a one-meter depth due to soil conditions or blocked passage, a lesser depth may be used within a low threat area with prior approval of the Authorizing Official (AO) if the carrier is encased within the center of mass of approximately 20 centimeters (8 inches) of concrete. (CAT I finding)

4. Check that the buried carrier departs and enters a building through the building's concrete slab or basement wall. NOTE: As an alternative all portions of the PDS above the one-meter (39 inches) depth and not within a CAA (e.g., a PDS rising to a pull box on the side of a building) must meet the requirements of a Category 2 hardened carrier. (CAT I finding)
 
5. Check that manholes or any other access (e.g., hand hole) to the buried PDS are secured with a PDS lock or an alarm. The PDS lock must be visible for daily inspection. If a PDS lock cannot be used due to the physical construction of the manhole, then a standard locking manhole cover and micro-switch alarm should be used. NOTE: As an alternative to a PDS lock or approved micro-switch alarms, manhole covers may be completely welded around the opening surface to impede opening and provide for clear evidence of penetration. Spot-welding is not acceptable.  If operational security needs dictate exceeding the STIG requirements, the site is always free to expand upon and increase their security posture by welding manhole covers. However, prior to this alternative method being instituted, the site must conduct and document an in-depth THREAT Assessment for their AOR and the assessment requires Senior Agency Official approval. This approval will be maintained on file. Also, daily visual inspections are still required per CNSSI 7003, Section X, para b. 3. (CAT I finding)

NOTE: The USD(I) Policy has determined the PDS Locks referred to in the CNSSI 7003 as Tamper Indicative Padlock with a wire loop seal and Tamper Evident Seal ARE NOT permitted for use in the DoD. This is because neither product was properly vetted and listed by the DoD Lock Program. ONLY the SG 8077 Changeable Combination Padlock is to be used for securing Buried PDS manhole covers protecting SIPRNet within the DoD.

6. If the carrier is buried in a MEDIUM threat location, check to ensure it is buried a minimum of 1 meter (39 inches) below the surface AND be encased within the center of mass of approximately 20 centimeters (8 inches) of concrete. NOTE: A concrete and steel container of sufficient size (to preclude surreptitious penetration in a period less than two hours as confirmed by laboratory tests) may be used in lieu of the 20 centimeters (8 inches) of concrete. (CAT I finding)

NOTE for Reviewers: If portions of the buried carrier cannot be checked due to being physically inaccessible, conduct whatever physical review is possible and attempt to validate PDS construction by reviewing contract/build documents, engineering drawings or certification documents from installation engineers that contain information about the physical makeup of the buried carrier.

7. Check the PDS is not within an Uncontrolled Access Area (UAA). (CAT I finding)"
  desc 'fix', "The following requirements must be applied to Exterior PDS:

1. Ensure the buried carrier is constructed of conduit consisting of EMT, rigid pipe, PVC, or a similar type of plastic electrical conduit.
  
2. Ensure all connections are permanently sealed completely around all mating surfaces (e.g., welding, epoxy, fusion, or PVC glue).
  
3. Ensure the PDS is buried a minimum of 1 meter (39 inches) below the surface and on the property (in a LOW Threat area within CONUS) owned or leased by the U.S. Government or the contractor having control of the PDS.

NOTE: As an alternative, if the carrier cannot be buried to a one-meter depth due to soil conditions or blocked passage, a lesser depth may be used within a low threat area with prior approval of the Authorizing Official (AO) if the carrier is encased within the center of mass of approximately 20 centimeters (8 inches) of concrete.
 
4. Ensure the buried carrier departs and enters a building through the building's concrete slab or basement wall.

NOTE: As an alternative, all portions of the PDS above the 1 meter (39 inches) depth and not within a CAA (e.g., a PDS rising to a pull box on the side of a building) must meet the requirements of a Category 2 hardened carrier.
   
5. Ensure that manholes or any other access (e.g., hand hole) to the buried PDS are secured with a PDS lock or an alarm. The PDS lock must be visible for daily inspection. If a PDS lock cannot be used due to the physical construction of the manhole, then a standard locking manhole cover and micro-switch alarm should be used.

NOTE: As an alternative to a PDS lock or approved micro-switch alarms, manhole covers may be completely welded around the opening surface to impede opening and provide for clear evidence of penetration. Spot-welding is not acceptable. If operational security needs dictate exceeding the STIG requirements, the site is always free to expand upon and increase their security posture by welding manhole covers. However, prior to this alternative method being instituted, the site must conduct and document an in-depth THREAT Assessment for their AOR and the assessment requires Senior Agency Official approval. This approval will be maintained on file. Also, daily visual inspections are still required per CNSSI 7003, Section X, para b. 3.  (CAT I finding).

NOTE: The USD(I) Policy has determined the PDS Locks referred to in the CNSSI 7003 as Tamper Indicative Padlock with a wire loop seal and Tamper Evident Seal ARE NOT permitted for use in the DoD. This is because neither product was properly vetted and listed by the DoD Lock Program. ONLY the SG 8077 Changeable Combination Padlock is to be used for securing Buried PDS manhole covers protecting SIPRNet within the DoD.

6. If the carrier is buried in a MEDIUM threat location, ensure it is buried a minimum of 1 meter (39 inches) below the surface AND be encased within the center of mass of approximately 20 centimeters (8 inches) of concrete. NOTE: A concrete and steel container of sufficient size (to preclude surreptitious penetration in a period less than two hours as confirmed by laboratory tests) may be used in lieu of the 20 centimeters (8 inches) of concrete.

7. Ensure the PDS is not located within an Uncontrolled Access Area (UAA)."
  impact 0.7
  ref 'DPMS Target Traditional Security Checklist'
  tag check_id: 'C-49162r865842_chk'
  tag severity: 'high'
  tag gid: 'V-245731'
  tag rid: 'SV-245731r865845_rule'
  tag stig_id: 'CS-04.01.04'
  tag gtitle: 'CS-04.01.04'
  tag fix_id: 'F-49117r865844_fix'
  tag 'documentable'
  tag legacy: ['V-30969', 'SV-41011r4_rule']
end
