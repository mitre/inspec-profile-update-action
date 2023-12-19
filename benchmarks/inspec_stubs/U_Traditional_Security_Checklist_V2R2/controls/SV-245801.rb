control 'SV-245801' do
  title 'Information Security (INFOSEC) - Secure Room Storage Standards - Intrusion Detection System (IDS)'
  desc 'Failure to meet standards for maintenance and validation of structural integrity of the physical perimeter surrounding a secure room (AKA: collateral classified open storage area) IAW DoD Manual 5200.01, Volume 3, could result in the undetected loss or compromise of classified material.  Using a physical intrusion detection system enables immediate detection of attempted and/or actual intrusion into a secure room space.  This is often the best supplemental protective measure (vice using 4-hour random checks) due to providing capability for immediate detection, and for immediate response to assess and counter the threat to the secure room space.  Use of 4-hour checks may be adequate if supported by a risk assessment, but will not provide the immediate detection and response capability of a properly installed IDS.  It is required that a risk assessment be conducted to determine which of these two intrusion detection methods (use of IDS OR 4-hour random checks) is appropriate for any particular location.

REFERENCES:

CJCSI 6510.01F, INFORMATION ASSURANCE (IA) AND SUPPORT TO COMPUTER NETWORK DEFENSE (CND), Enclosure C, paragraphs 24.j. and 34.

NIST Special Publication 800-53 (SP 800-53), Rev 4, Controls: 
MP-4, PE-3, PE-5 and PE-6

DoD Manual 5200.01, Volume 3, SUBJECT: DoD Information Security Program: Protection of Classified Information: Encl 3, paragraphs 3.a.(3), 3.b.(1), 3.b.(3)(a)&(b) and paragraph 4.

The Information Security Oversight Office (ISOO): http://www.archives.gov/isoo/   Implementing Directive for Protection of Classified (for Executive Order 13526), 32 CFR Parts 2001 and 2003 Classified National Security Information: paragraph 2001.43 Storage, (2) Secret.

DoD 5220.22-M (NISPOM), Incorporating Change 2, 18 May 2016, Chapter 5, Section 3; paragraphs 5-306.b., 5-307.a., 5-307.b. & Section 9; paragraphs 5-900 and 5-904.'
  desc 'check', 'Background Details:
  
Except for storage in a GSA-approved container (AKA: safe) or a vault built to FED STD 832, one of the following supplemental controls is required for secure rooms or areas containing SIPRNet (secret) assets, provided the CC/S/A senior agency official determines in writing that security-in-depth exists:
 
(1) Inspection of the container or open storage area every four hours by an employee cleared at least to the Secret level; or 
(2) An IDS with the personnel responding to the alarm arriving within 30 minutes of the alarm annunciation.

IMPORTANT NOTE:  Random checks not exceeding 4-hours are an allowable alternative to IDS ONLY if supported by a valid risk assessment.  

Prior to the installation of an IDS, the site shall perform a risk analysis to determine the threat, vulnerabilities, security-in-depth countermeasures,  the acceptability of risk, potential cost savings, procedural requirements, and potential cost of additional manpower associated with random checks of the secure room as an alternative to IDS.  

Random checks and risk analysis are each covered as separate checks elsewhere in this checklist.  

This particular check for IDS is Not Applicable (NA) if random checks are properly conducted and are supported by the risk analysis and security-in-depth approved by the senior agency official in writing.

In summary this check is to validate an IDS is being used AND that it is supported by a valid risk assessment AND  security-in-depth approved by the senior agency official in writing. 
 
Checks: 

1. Check to ensure that all secure rooms/classified open storage areas that afford access to classified SIPRNet equipment (servers, routers, switches, comm equipment, work stations, DASD, etc...) are protected by an Intrusion Detection System (IDS) *unless continually occupied. (CAT I)

2. Where IDS is being used check to ensure that its use is supported by both a RISK ASSESSMENT and a SECURITY-IN-DEPTH DETERMINATION * (Security-In-Depth Determination must IN WRITING by the C/S/A senior agency (security) official) that specifically addresses the secure room or open storage space. (CAT II) 

TACTICAL ENVIRONMENT:  This check is applicable where Secure Rooms are used to protect classified materials or systems in a tactical environment. The only exception will be for urgent (short term) tactical operations or other contingency situations where fixed facilities and equipment are not yet present or incapable of being used.'
  desc 'fix', '1. All secure rooms (AKA: collateral classified open storage areas) that afford access to classified SIPRNet equipment (servers, routers, switches, comm equipment, work stations, DASD...) must be protected by an Intrusion Detection System (IDS) unless continuously occupied. 

IMPORTANT NOTE:  Random checks not exceeding 4-hours are an allowable alternative to IDS ONLY if supported by a valid risk assessment and security-in-depth.  

Random checks and risk analysis are each covered as separate requirements elsewhere in this document. This particular requirement for IDS is Not Applicable (NA) if random checks are properly conducted and are supported by the risk analysis and security-in-depth approved by the senior agency (security) official in writing.

2. Prior to the installation of an IDS, the site must perform a risk analysis to determine the threat, vulnerabilities, security-in-depth countermeasures, the acceptability of risk, potential cost savings, procedural requirements, and potential cost of additional manpower associated with random checks of each secure room as an alternative to IDS. 

3. Security-in-Depth for each secure room must be approved *in writing* by the CC/S/A senior agency official (senior official for security) 

In summary: An IDS must be used as a supplemental protective measure AND it must be supported both by a valid risk assessment AND security-in-depth as approved in writing by the senior agency official.'
  impact 0.7
  ref 'DPMS Target Traditional Security Checklist'
  tag check_id: 'C-49232r770063_chk'
  tag severity: 'high'
  tag gid: 'V-245801'
  tag rid: 'SV-245801r822853_rule'
  tag stig_id: 'IS-02.01.07'
  tag gtitle: 'IS-02.01.07'
  tag fix_id: 'F-49187r770064_fix'
  tag 'documentable'
  tag legacy: ['V-31274', 'SV-41541r3_rule']
end
