control 'SV-245803' do
  title 'Information Security (INFOSEC) - Secure Room Storage Standards - Interior Motion Detection'
  desc 'Failure to meet standards for ensuring that there is structural integrity of the physical perimeter surrounding a secure room (AKA: collateral classified open storage area) IAW DoD Manual 5200.01, Volume 3 could result in the undetected loss or compromise of classified material.  Motion detection located interior to secure rooms provides the most complete/overarching coverage of any Intrusion Detection System (IDS) alarm sensor.  While most sensors like BMS alarm contacts, glass break detectors, etc. are only able to detect potential intrusion at specific locations, use of motion detection provides a capability to protect large areas with "blanket coverage" generally using fewer sensors.

Principles and considerations for "ideal" employment of motion sensors are:

- Consolidate critical assets in specific areas versus throughout a large room or facility. For instance rather than having classified servers and equipment in multiple locations in a five-story facility (entirely designated for classified open storage) consolidate classified assets on a single floor or even an area on that floor. That might allow for reducing the space designated as classified open storage (AKA: secure room) and reduce costs and simplify protection of assets.  

- Conversely some would argue that dispersing assets over a larger area enhances security by not putting all critical assets in one place. This is true to an extent - especially if we are considering redundant assets for COOP / disaster recovery but most often the reason for dispersing classified assets over large comes down to lack of foresight and planning.

- Cover avenues of approach in layers so you can detect initial breeches of secured space and subsequent movement within. This approach is actually very good if you have a timely response force available and you are protecting a large facility.

- Cover perimeter access points such as doors, windows, and openings greater than 96 sq. inches. Use of point sensors (BMS, vibration, etc., are probably best in these situations but supplementation by motion can be extremely effective.

- Cover areas that cannot be directly observed by employees from within or directly outside the protected space. For instance in a secure room/area this might include areas above suspended ceilings, below raised floors, behind major pieces of equipment or other things that cause significant obstruction of visual observation (especially along avenues of approach or along perimeter walls).

- Cover large open areas by careful placement of motion detection. Combinations of 360-degree and wall-mounted detectors considering equipment racks, walls, avenues of approach, etc. can effectively cover larger areas with fewer sensors.

- Complete coverage of large areas and all avenues of approach is ideal but often funds are limited and sensors cannot be employed to provide blanket coverage. In such instances there are two approaches that can be used:

   * One is to cover the most critical assets directly (e.g., classified DoDIN servers, routers, DASD and other major IT technology).

   * Second approach is to conduct an assessment of the space to determine the most effective employment of limited sensors considering both avenues of approach and the actual location of critical assets in the space.   

NOTE:  The second approach can be incorporated under the process of conducting a risk assessment and in conjunction with a determination and approval of security-in-depth countermeasures from the Senior Agency Official (SAO). This risk-based approach is based directly on requirements from the DoD Manual 5200.01, V3 and is in line with the current direction DoD is taking with regard to management of risk.  

REFERENCES:

CJCSI 6510.01F, INFORMATION ASSURANCE (IA) AND SUPPORT TO COMPUTER NETWORK DEFENSE (CND), Enclosure C, paragraphs 24.j. and 34.

NIST Special Publication 800-53 (SP 800-53), Rev 4, Controls: 
MP-4, PE-3, PE-5 and PE-6

DoD Manual 5200.01, Volume 3, SUBJECT: DoD Information Security Program: Protection of Classified Information: Appendix to Enclosure 3, paragraph 1.b.(4)(a) and 2.e.(3) &  (5).

The Information Security Oversight Office (ISOO): http://www.archives.gov/isoo/   Implementing Directive for Protection of Classified (for Executive Order 13526), 32 CFR Parts 2001 and 2003 Classified National Security Information: paragraph 2001.43 Storage, (2) Secret.

DoD 5200.22-M (NISPOM), Incorporating Change 2, 18 May 2016, Chapter 5, Section 9. Intrusion Detection Systems.'
  desc 'check', 'The following applies where IDS is used in lieu of 4-hour random checks, for secure rooms or collateral classified open storage areas containing SIPRNet assets:

Checks:
1.  Check at sites where IDS is being used and:

    -  There is NO RISK ASSESSMENT approved by the Component Authorizing Official (AO) or

    -  The risk assessment does not specifically provide a detailed evaluation of the need for motion sensor employment, including a thorough assessment of the most effective and efficient methods for employment of motion detection and/or

    -  There is NO SECURITY-IN-DEPTH DETERMINATION *IN WRITING by the CC/S/A Senior Agency Official (SAO)(Security/INFOSEC) that considers factors contained in the risk assessment and specifically focuses on the collateral classified secure room/open storage space:

Check to ensure that secure rooms or areas where classified SIPRNet equipment and/or associated media is stored in the open is protected with interior motion detection sensors; e.g., ultrasonic and passive infrared, during times when the specific area containing the classified material is closed or not under continuous observation and control by a cleared employee. 

Use of dual technology sensors is authorized when one technology transmits an alarm condition independently from the other technology.  A failed detector shall cause an immediate and continuous alarm condition.  

Employment of motion detectors need not cover 100% of the entire secure room space (although that is recommended) but shall minimally (directly) cover any SIPRNet assets (equipment or media) that are accessible (not stored within a GSA approved container (safe)) within the secure room or area.

2. Where a proper risk assessment signed by the AO, which specifically considers both the number and employment (positioning) of motion sensors in the secure room space and a supporting Security-in-Depth Determination signed by the SAO are both available:

Check that motion sensors are either employed to directly cover all areas within the secure room containing SIPRNet assets OR that motion sensors are employed in the secure room space as specifically detailed in the risk assessment.

NOTE:  Unless adequately detailed and justified in the risk assessment, motion detectors placed to cover only doors that are protected with BMS alarm contacts are not sufficient to meet this requirement/check.  

TACTICAL ENVIRONMENT:  This check is applicable where Secure Rooms are used to protect classified materials or systems in a tactical environment. The only exception will be for urgent (short term) tactical operations or other contingency situations where fixed facilities and equipment are not yet present or incapable of being used.'
  desc 'fix', 'Compliance with the following two considerations is required where an IDS is used in lieu of 4-hour random checks, for secure rooms or collateral classified open storage areas containing SIPRNet assets:

1.  Where IDS is being used BUT there is NO RISK ASSESSMENT approved by the Component Authorizing Official (AO) and/or a SECURITY-IN-DEPTH DETERMINATION *IN WRITING by the CC/S/A Senior Agency Official (SAO) (Security/INFOSEC) that specifically addresses the secure room or open storage space OR the risk assessment does not specifically provide for a detailed evaluation of the need for motion sensor employment, including a thorough assessment of the most effective and efficient methods for employment of motion detection:

Secure rooms or areas where classified SIPRNet equipment and/or associated media is stored in the open must be protected with interior motion detection sensors; e.g., ultrasonic and passive infrared when the specific area containing the classified material is closed or not under continuous observation and control of a cleared employee.  

Use of dual technology is authorized when one technology transmits an alarm condition independently from the other technology. A failed detector shall cause an immediate and continuous alarm condition.

Employment of motion detectors need not cover 100% of the entire secure room space (although that is recommended) but shall minimally (directly) cover any SIPRNet assets (equipment or media) that are accessible (not stored within a GSA approved container (safe)) within the secure room or area.  

2. At a minimum all SIPRNet connected equipment must be directly covered by motion sensors OR  motion sensors must be employed in the secure room space as "specifically detailed" in the risk assessment, which is approved by the Component Authorizing Official (AO).

Unless adequately detailed in the risk assessment, motion detectors placed to cover only doors that are protected with BMS alarm contacts are not sufficient to meet this requirement/check.'
  impact 0.7
  ref 'DPMS Target Traditional Security Checklist'
  tag check_id: 'C-49234r770069_chk'
  tag severity: 'high'
  tag gid: 'V-245803'
  tag rid: 'SV-245803r770313_rule'
  tag stig_id: 'IS-02.01.09'
  tag gtitle: 'IS-02.01.09'
  tag fix_id: 'F-49189r770070_fix'
  tag 'documentable'
  tag legacy: ['SV-41543r3_rule', 'V-31276']
end
