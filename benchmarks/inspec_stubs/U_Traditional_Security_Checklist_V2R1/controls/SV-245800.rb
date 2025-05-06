control 'SV-245800' do
  title 'Information Security (INFOSEC) - Vault Storage/Construction Standards'
  desc 'Failure to meet standards IAW the DoD Manual 5200.01, Volume 3, Appendix to Enclosure 3, for ensuring that there is required structural integrity of the physical perimeter surrounding a classified storage vault could result in the undetected loss or compromise of classified material.

REFERENCES:

CJCSI 6510.01F, INFORMATION ASSURANCE (IA) AND SUPPORT TO COMPUTER NETWORK DEFENSE (CND), Enclosure C, paragraphs 24.j. and 34.

NIST Special Publication 800-53 (SP 800-53), Rev 4, Controls: 
MP-4, PE-3 and PE-5

DoD Manual 5200.01, Volume 3, SUBJECT: DoD Information Security Program: Protection of Classified Information: Appendix to Encl 3, para 1.a.(1) & (2).

The Information Security Oversight Office (ISOO): http://www.archives.gov/isoo/   Implementing Directive for Protection of Classified (for Executive Order 13526), 32 CFR Parts 2001 and 2003 Classified National Security Information: paragraph 2001.43 Storage, (2) Secret.

DoD 5200.22-M (NISPOM), Incorporating Change 2, 18 May 2016, Chapter 5,  Section 8, Construction Requirements, paragraph 5-802. Construction required for Vaults.'
  desc 'check', 'For vaults containing inspectable SIPRNet assets check with supporting Facility Engineers to ensure it is properly constructed IAW one of the following two specifications:

1.  As a Class A vault (concrete poured-in-place) built to Federal Standard (FED STD) 832 and specifically check/validate the following:
 
a. Floor and Walls. Eight inches of reinforced concrete. Walls are to extend to the underside of the roof slab above.
 
b. Roof/True Ceiling. Monolithic reinforced-concrete slab of thickness to be determined by structural requirements, but not less than the floors and walls.
 
c.  "True" vaults must have a Class 5 Vault Door and Frame and be fitted with an FF-L-2740 combination lock.  The vault door and frame unit must conform to Federal Specification AA-D-600 Class 5 vault door with lock meeting Federal Specification FF-L-2740. Ensure it is not an armory vault door, which should have a GSA label (silver with red letters) stating that it is a "GSA Approved Armory Vault Door".  AN ARMORY DOOR IS NOT APPROVED FOR CLASSIFIED STORAGE - AA&E STORAGE ONLY.  The "proper" security vault door label reads "GSA Approved Security Vault Door" (label also silver with red letters). The difference between the two doors is that armory vault doors are fitted with Federal Specification FF-L-2937 mechanical combination locks.    Facility Engineer (FE) construction certificates or other documentation should be requested to ensure construction standards are met.  Often these certificates are posted on the inside of the vault near the door.

2. As a Class B vault (GSA-approved modular vault) meeting Federal Specification AA-V-2737, Modular Vault Systems, April 25, 1990, with Amendment 2, October 30, 2006.

NOTE: 
Here again, normally FE certification documentation will be posted within the vault, but it is OK if such documentation is on file elsewhere at the site.
  
The DoD Lock Program WEB Portal provides detailed specifications for vaults and ordering instructions for doors. Available through DoD Lock Program at the Documents, Federal Specifications tab for Federal Specifications or Documents, Directives and Guidance tab for Federal Standards and Military Handbooks:

https://locks.navfac.navy.mil 
        
TACTICAL ENVIRONMENT:  This check is applicable where vaults are used to protect classified materials or systems in a tactical environment.'
  desc 'fix', 'Vaults containing inspectable SIPRNet assets must have documented confirmation from supporting Facility Engineers to ensure each is built to the following standards:

1.  As a Class A vault (concrete poured-in-place) built to Federal Standard (FED STD) 832 and specifically check/validate the following:
 
a. Floor and Walls. Eight inches of reinforced concrete. Walls are to extend to the underside of the roof slab above.
 
b. Roof/True Ceiling. Monolithic reinforced-concrete slab of thickness to be determined by structural requirements, but not less than the floors and walls.
 
c.  Class 5 Vault Door and Frame and be fitted with an FF-L-2740 combination lock.  The vault door and frame unit must conform to Federal Specification AA-D-600 Class 5 vault door with lock meeting Federal Specification FF-L-2740. It cannot be an armory vault door, which should have a GSA label (silver with red letters) stating that it is a "GSA Approved Armory Vault Door".  AN ARMORY DOOR IS NOT APPROVED FOR CLASSIFIED STORAGE - AA&E STORAGE ONLY.  The "proper" security vault door label must read:  "GSA Approved Security Vault Door" (label also silver with red letters).  The difference between the two doors is that armory vault doors are fitted with Federal Specification FF-L-2937 mechanical combination locks.
    
2. As a Class B vault (GSA-approved modular vault) meeting Federal Specification AA-V-2737, Modular Vault Systems, April 25, 1990, with Amendment 2, October 30, 2006.

Facility Engineer (FE) construction certificates or other documentation must be available to ensure construction standards are met. Often these certificates are posted on the inside of the vault near the door, but can be on file elsewhere at the site.'
  impact 0.7
  ref 'DPMS Target Traditional Security Checklist'
  tag check_id: 'C-49231r770308_chk'
  tag severity: 'high'
  tag gid: 'V-245800'
  tag rid: 'SV-245800r770310_rule'
  tag stig_id: 'IS-02.01.06'
  tag gtitle: 'IS-02.01.06'
  tag fix_id: 'F-49186r770309_fix'
  tag 'documentable'
  tag legacy: ['V-31273', 'SV-41540r3_rule']
end
