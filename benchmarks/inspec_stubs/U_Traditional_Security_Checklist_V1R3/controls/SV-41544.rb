control 'SV-41544' do
  title 'Information Security (INFOSEC) - Secure Room Storage Standards - Structural Integrity Checks'
  desc 'Failure to ensure that there is structural integrity of the physical perimeter surrounding a secure room (AKA: collateral classified open storage area) IAW DoD Manual 5200.01, Volume 3 could result in the undetected loss or compromise of classified material.

REFERENCES:

CJCSI 6510.01F, INFORMATION ASSURANCE (IA) AND SUPPORT TO COMPUTER NETWORK DEFENSE (CND), Enclosure C, paragraphs 24.j. and 34.

NIST Special Publication 800-53 (SP 800-53), Rev 4, Controls: PE-3.(1) & (2), PE-6 (4).

DoD Manual 5200.01, Volume 3, SUBJECT: DoD Information Security Program: Protection of Classified Information:  Glossary, Part II, Definitions: Security-in-Depth

DoD 5200.22-M (NISPOM), Incorporating Change 2, 18 May 2016, paragraphs 5-306.a & 8-302.b. Physical and Environmental Protection.'
  desc 'check', 'BACKGROUND:
In spite of all physical security defensive devices deployed, the possibility of an intrusion always exists. The highest fence can be scaled, the densest wall can be breached and the stoutest lock can be compromised.  Even highly sophisticated alarm systems can be contravened by a knowledgeable professional.  It is therefore necessary to institute a system of checks to physically inspect secure room perimeters to check for signs of attempted intrusions and ensure that structural integrity of the perimeter is maintained. 

This requirement is concerned with ensuring there is periodic visual validation of structural integrity of secure room/collateral classified open storage area perimeters containing SIPRNet assets and associated media.  It ensures that any breach or attempted breach of the walls, true floors and true ceilings of a secure area (portions which are not readily visible) are discovered in a timely manner.
 
In Check #1 there are 3 different situations covered and each requires a different inspection frequency for physical/visual validation of structural integrity. 
 
Check #1. Check to ensure that structural integrity of secure rooms or spaces containing SIPRNet equipment is validated as follows: 
 
Situation #1 (No structural integrity checks required): If interior IDS (motion detection) is *properly employed (*directly covering all SIPRNet assets) within the secure room or collateral classified open storage space where classified SIPRNet assets are located AND under raised floor spaces (if applicable) AND above suspended ceiling spaces (if applicable), then no physical check for structural integrity is required.  This is contingent upon the interior motion sensors being activated when the room is closed or unattended, and that the sensors work properly as determined by required checks of sensor functionality.
  
Situation #2 (Monthly checks required): If motion sensors are properly employed ONLY within the secure room space where classified assets are located, then a visual check of spaces below raised floor, above suspended ceilings and anywhere else the perimeter of the secure area cannot be readily observed must be conducted on at least a monthly basis.  The goal is to visually inspect all walls, true floor and true ceiling perimeters for signs of breach or attempted breach.
   
Situation #3 (Weekly checks required): When random checks (not exceeding 4-hours) of secure rooms or open storage spaces are used in lieu of IDS then the checks specified in situation #2 for above suspended ceilings and below raised floors must be conducted at least weekly.  The increased frequency of checks is due to the significant vulnerability of the SIPRNet assets to undetected attack from portions of the perimeter that cannot be readily observed.  NOTE: Physical inspection of the perimeter walls, floor and ceiling can be greatly expedited and may be conducted without ladders or other equipment where there are no false/suspended ceilings and/or raised floors within or surrounding the secure room or area.
   
NOTE: If the entire perimeter of the secure room or area containing SIPRNet assets is surrounded by a secret or top secret (TS) Controlled Access Area (CAA) the frequency of structural integrity checks may be reduced to once every two weeks. This is due to the increased security-in-depth provided by the CAA. A secret or TS CAA is an area where unescorted access is granted only to those individuals who have a secret or higher security clearance. All others are escorted by cleared employees. The DoD does not provide specific physical security requirements for a CAA but allows each CC/S/A Senior Agency Official (SAO) for Information Security the authority to establish such standards. All the Services have established standards for CAAs within their Protected Distribution System (PDS) implementing guidelines. Minimally all require some form of access control methodology (AECS/guards/reception…)be in place to ensure only properly vetted and cleared personnel have unescorted access to a CAA.

Check #2. Check to ensure there are written procedures developed for the checks and that the checks are documented and maintained on file for a minimum of 90 days.  Where discrepancies (holes in perimeter or other signs of successful or attempted access) are noted these checks will be maintained indefinitely or until an inquiry determines the cause of the discrepancy.
                  
TACTICAL ENVIRONMENT:  This check is applicable where Secure Rooms are used to protect classified materials or systems in a tactical environment. The only exception will be for urgent (short term) tactical operations or other contingency situations where fixed facilities and equipment are not yet present or incapable of being used.'
  desc 'fix', 'BACKGROUND:
This fix is concerned with ensuring there is periodic visual validation of structural integrity of secure room/collateral classified open storage area perimeters containing SIPRNet assets and associated media.  It ensures that any breach or attempted breach of the walls, true floors and true ceilings of a secure area (which are not readily visible) are discovered in a timely manner.

In requirement #1 there are 3 different situations covered and each requires a different level of physical/visual validation for structural integrity. 
 
Requirement #1. Structural integrity of secure rooms or spaces containing SIPRNet equipment must be validated in each situation as follows: 
 
Situation #1 (No structural integrity checks required): If interior IDS (motion detection) is *properly employed (*directly covering all SIPRNet assets) within the secure room or collateral classified open storage space where classified SIPRNet assets are located AND under raised floor spaces (if applicable) AND above suspended ceiling spaces (if applicable), then no physical check for structural integrity is required.  This is contingent upon the interior motion sensors being activated when the room is closed or unattended, and that the sensors work properly as determined by required checks of sensor functionality.
  
Situation #2 (Monthly checks required): If motion sensors are properly employed ONLY within the secure room space where classified assets are located, then a visual check of spaces below raised floor, above suspended ceilings and anywhere else the perimeter of the secure area cannot be readily observed must be conducted on at least a monthly basis.  The goal is to visually inspect all walls, true floor and true ceiling perimeters for signs of breach or attempted breach.
   
Situation #3 (Weekly checks required): When random checks (not exceeding 4-hours) of secure rooms or open storage spaces are used in lieu of IDS then the checks specified in situation #2 for above suspended ceilings and below raised floors must be conducted at least weekly.  The increased frequency of checks is due to the significant vulnerability of the SIPRNet assets to undetected attack from portions of the perimeter that cannot be readily observed.  NOTE: Physical inspection of the perimeter walls, floor and ceiling can be greatly expedited and may be conducted without ladders or other equipment where there are no false/suspended ceilings and/or raised floors within or surrounding the secure room or area.
   
NOTE: If the entire perimeter of the secure room or area is surrounded by a secret or top secret (TS) Controlled Access Area (CAA) the frequency of structural integrity checks may be reduced to once every two weeks. This is due to the increased security-in-depth provided by the CAA. A secret or TS CAA is an area where unescorted access is granted only to those individuals who have a secret or higher security clearance. All others are escorted by cleared employees. The DoD does not provide specific physical
security requirements for a CAA but allows each CC/S/A Senior Agency Official (SAO) for Information Security the authority to establish such standards. All the Services have established standards for CAAs within their Protected Distribution System (PDS) implementing guidelines. Minimally all require some form of access control methodology (AECS/guards/reception…) be in place to ensure only properly vetted and cleared personnel have unescorted access to a CAA.

Requirement #2. There must be written procedures developed for the checks and that the checks are documented and maintained on file for a minimum of 90 days.  Where discrepancies (holes in perimeter or other signs of successful or attempted access) are noted these checks will be maintained indefinitely or until an inquiry determines the cause of the discrepancy.'
  impact 0.5
  ref 'DPMS Target Traditional Security'
  tag check_id: 'C-40019r12_chk'
  tag severity: 'medium'
  tag gid: 'V-31277'
  tag rid: 'SV-41544r3_rule'
  tag stig_id: 'IS-02.02.01'
  tag gtitle: 'Information Security (INFOSEC) - Secure Room Standards - Structural Integrity Check'
  tag fix_id: 'F-35188r9_fix'
  tag 'documentable'
  tag severity_override_guidance: 'The default finding is a CAT II. 
It may be lowered to a CAT III finding if it can be determined the perimeter checks are actually conducted as specified, but written procedures or documentation covering results of the checks are not developed or maintained.'
end
