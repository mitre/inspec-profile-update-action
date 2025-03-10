control 'SV-245863' do
  title 'Physical Security Program - Physical Security Plan (PSP) and/or Systems Security Plan (SSP) Development and Implementation with Consideration/Focus on Protection of Information System Assets in the Physical Environment'
  desc 'Failure to have a well-documented Physical Security/Systems Security program will result in an increased risk to DoD Information Systems; including personnel, equipment, media, material and documents.

REFERENCES:

DoD 5220.22-M (NISPOM), Incorporating Change 2, 18 May 2016
Chapter 8, Section 1, paragraphs 8-100, 8-101, 8-102, 8-301 and 8-302.b.&c.

DoD 5200.8-R Physical Security Program 
Chapters 1, 2 and 3

DoD Manual 5200.08 Volume 3, Physical Security Program: Access to DoD Installations, 
2 January 2019

NIST Special Publication 800-53 (SP 800-53) 
Controls: PE-1 through PE-20 and PL-1 & PL-2 

CJCSI 6510.01F, INFORMATION ASSURANCE (IA) AND SUPPORT TO COMPUTER NETWORK DEFENSE (CND), 9 February 2011 
Encl A, para 5.a.(1), Encl C, para: 24.j., 27., 28.b., and 34.'
  desc 'check', '1. Check to ensure there is a Physical Security Plan (PSP), either an organizational/site AND/OR an installation security plan in which granular security concerns and procedures at the site are addressed and considered. 

NOTE 1:  If a higher level installation or base plan is used ensure that it specifically addresses security concerns/procedures for the inspected organization or site.  Ideally, a local site or organization should always be included in the host installation security plan. If not, then a separately developed local (site/organization) Physical Security Plan (and/or Systems Security Plan (SSP)) is required, which integrates local security procedures for the site with the security-in-depth (SID) measures detailed in the host installation PSP.  The installation level PSP will likely not address granular security concerns for computer rooms and areas hosting information systems assets at individual installation sites.  Therefore the local organization(s) should still document specific protection measures covering SIPRNet and/or NIPRNet assets in a local PSP or in an SSP.    

2. Check to ensure security requirements of the computer room(s) (SIPRNet and/or NIPRNet) and collateral classified open storage areas (as applicable) are addressed and that guidance is provided to counter threats during peacetime, transition to war, and in wartime.  

3. Check to ensure the plan also addresses entry/access control procedures for the facility overall and for individual computer rooms/secure rooms or other areas housing network equipment (routers/crypto/switches, etc.). Use of an AECS, guards, lock & key systems, cipher locks, etc. should be specifically and thoroughly addressed in the plan.

4. Check to ensure that access control procedures cover requirements for various categories of persons expected to access the facility such as employees, visitors, vendors, facility maintenance, and foreign nationals.  

NOTE 2: To be complete the plan should specifically address access control of vendors (ie., vending machine deliveries), cleaning and food service personnel, cleared versus uncleared visitors, foreign national (FN) visitors, FN employees (OCONUS SOFA, liaison, exchange and REL partners).   

5. Finally check to ensure the plan addresses security measures and response (Emergency Planning Measures) to include application of Force Protection Conditions, anti-terrorism planning and measures, civil disturbances, natural disasters, crime and any other possible local disruptions of the mission. A thorough plan will include measures designed to detect, delay, assess and respond to intrusions and other emergency situations.

NOTE 3: If the plan or any of the critical elements of the plan (everything mentioned here) applicable to the specific site are missing - a finding should be written.                                     

TACTICAL ENVIRONMENT: The check is applicable for fixed (established) tactical processing environments where procedural documents (SOPs) should be in place.  Not applicable to a field/mobile environment.'
  desc 'fix', '1. Ensure there is a Physical Security Plan (PSP), either an organizational/site AND/OR an installation security plan in which granular security concerns and procedures at the site are addressed and considered.

NOTE 1:  If a higher level installation or base plan is used ensure that it specifically addresses security concerns/procedures for the inspected organization or site.  Ideally, a local site or organization should always be included in the host installation security plan. If not, then a separately developed local (site/organization) Physical Security Plan (and/or Systems Security Plan (SSP)) is required, which integrates local security procedures for the site with the security-in-depth (SID) measures detailed in the host installation PSP.  The installation level PSP will likely not address granular security concerns for computer rooms and areas hosting information systems assets at individual installation sites.  Therefore the local organization(s) should still document specific protection measures covering SIPRNet and/or NIPRNet assets in a local PSP or in an SSP.    

2.  Ensure security requirements of the computer room(s) (SIPRNet and/or NIPRNet) and collateral classified open storage areas (as applicable) are addressed and that guidance is provided to counter threats during peacetime, transition to war, and in wartime.
  
3. Ensure the plan also addresses entry/access control procedures for the facility overall and for individual computer rooms/secure rooms or other areas housing network equipment (routers/crypto/switches, etc.). Use of an AECS, guards, lock & key systems, cipher locks, etc. should be specifically and thoroughly addressed in the plan.

4. Ensure that access control procedures cover requirements for various categories of persons expected to access the facility such as employees, visitors, vendors, facility maintenance, and foreign nationals.  

NOTE 2: To be complete the plan should specifically address access control of vendors (i.e., vending machine deliveries), cleaning and food service personnel, cleared versus uncleared visitors, foreign national (FN) visitors, FN employees (OCONUS SOFA, liaison, exchange and REL partners). 
  
5. Finally, ensure the plan addresses security measures and response (Emergency Planning Measures) to include application of Force Protection Conditions, anti-terrorism planning and measures, civil disturbances, natural disasters, crime and any other possible local disruptions of the mission. A thorough plan will include measures designed to detect, delay, assess and respond to intrusions and other emergency situations.'
  impact 0.3
  ref 'DPMS Target Traditional Security Checklist'
  tag check_id: 'C-49294r770249_chk'
  tag severity: 'low'
  tag gid: 'V-245863'
  tag rid: 'SV-245863r822925_rule'
  tag stig_id: 'PH-01.03.01'
  tag gtitle: 'PH-01.03.01'
  tag fix_id: 'F-49249r822924_fix'
  tag 'documentable'
  tag legacy: ['SV-42819r3_rule', 'V-32482']
end
