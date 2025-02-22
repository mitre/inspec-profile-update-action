control 'SV-245804' do
  title 'Information Security (INFOSEC) - Secure Room Storage Standards - Four (4) Hour Random Checks in Lieu of Using Intrusion Detection System (IDS)'
  desc 'Failure to meet standards for ensuring that there is structural integrity of the physical perimeter surrounding a secure room (AKA: collateral classified open storage area) IAW DoD Manual 5200.01, Volume 3 could result in the undetected loss or compromise of classified material.

Using a physical intrusion detection system enables immediate detection of attempted and/or actual intrusion into a secure room space.  This is often the best supplemental protective measure (vice using 4-hour random checks) due to providing capability for immediate detection, and for immediate response to assess and counter the threat to the secure room space.  Use of 4-hour checks may be adequate if supported by a risk assessment, but will not provide the immediate detection and response capability of a properly installed IDS.  It is required that a risk assessment be conducted to determine which of the two intrusion detection methods (use of IDS OR 4-hour random checks) is appropriate for any particular location.  If the risk assessment results in a determination that use of 4-hour random checks is the most cost efficient supplemental control (vice IDS) to protect SIPRNet assets contained in secure rooms, the manner in which the checks are conducted can greatly impact the effectiveness of the checks.  Thorough physical checks conducted on a frequent basis can reduce the time between an attempted or actual intrusion and time of discovery - during random checks. 

REFERENCES:

CJCSI 6510.01F, INFORMATION ASSURANCE (IA) AND SUPPORT TO COMPUTER NETWORK DEFENSE (CND), Enclosure C, paragraphs 24.j. and 34.

NIST Special Publication 800-53 (SP 800-53), Rev 4, Controls: 
MP-4, PE-3, PE-5 and PE-6

DoD Manual 5200.01, Volume 3, SUBJECT: DoD Information Security Program: Protection of Classified Information: Enclosure 3, paragraph 3.b.(3)(a) and 4.

The Information Security Oversight Office (ISOO): http://www.archives.gov/isoo/   Implementing Directive for Protection of Classified (for Executive Order 13526), 32 CFR Parts 2001 and 2003 Classified National Security Information: Subpart E - Safeguarding. paragraph 2001.40 General. (b) and paragraph 2001.43 Storage, (2) Secret.

DoD 5200.22-M (NISPOM), Incorporating Change 2, 18 May 2016, paragraph 5-306. Closed Areas.; paragraph 5-307 Supplemental Protection. b. & c.; *paragraphs 8-102., 8-201. & 8-301.e. (*for risk assessment requirements)'
  desc 'check', 'Background:

This check is concerned with using random checks as the required supplemental control of secure room/collateral classified open storage area space (containing SIPRNet assets) - instead of IDS.  

Checks:

Check #1. Use of random checks in lieu of IDS must be supported by a valid risk assessment (addressing each secure room or area) that specifically considers the threat, vulnerabilities, security-in-depth countermeasures, acceptability of risk, potential cost savings, procedural requirements, and potential cost of additional manpower associated with random checks of the secure areas - as an alternative to IDS.  

Check #2. The frequency of random checks shall not exceed 4-hours when the secure area space is not attended. 

Check #3. Checks must be conducted by guards/employees who are cleared to at least the Secret level.  

Check #4.  Checks will be conducted of each door (primary and all secondary), each window, and each opening exceeding 96 square inches (which are required to be protected with either bars, expanded metal grills, commercial metal sounds baffles) to ensure they are properly secured.  Additionally all traversable space surrounding the exterior of the Secure Room should be viewed by the checker by walking around the entire perimeter.  

Check #5.  Checks must be supported by written procedures/instructions for the checkers and results of checks must be recorded.  

Check #6. Locally developed checklists or the Standard Form (SF) 701 must be used to document checks.  Completed checklists should be maintained on-hand for at least 90-days as an audit trail or indefinitely if discrepancies were noted during any checks.

It is important to note that random checks are an allowable alternative to IDS *ONLY* if supported by a valid risk assessment AND security-in-depth countermeasures as determined in writing by the C/S/A senior security official.  Otherwise this is a finding.  

Use of IDS and risk analysis are each covered as separate checks elsewhere in this document.   

This particular check (random checks of secure rooms) is Not Applicable (NA) if IDS is used.  

In summary this check must validate that random checks not exceeding 4-hours are being used AND that it is supported by a valid risk assessment along with security-in-depth countermeasures.                            

TACTICAL ENVIRONMENT:  This check is applicable where Secure Rooms are used to protect classified materials or systems in a tactical environment. The only exception will be for urgent (short term) tactical operations or other contingency situations where fixed facilities and equipment are not yet present or incapable of being used.'
  desc 'fix', 'Background:

This requirement is concerned with using random checks as the required supplemental control of secure room/collateral classified open storage area space (containing SIPRNet assets) - instead of IDS.  

Fixes:

1. Use of random checks in lieu of IDS must be supported by a valid risk assessment (addressing each secure room or area) that specifically considers the threat, vulnerabilities, security-in-depth countermeasures, acceptability of risk, potential cost savings, procedural requirements, and potential cost of additional manpower associated with random checks of the secure areas - as an alternative to IDS.  

2. The frequency of random checks must not exceed 4-hours when the secure area space is not attended. 

3. Checks must be conducted by guards/employees who are cleared to at least the Secret level.  

4. Checks must be conducted of each door (primary and all secondary), each window, and each opening exceeding 96 square inches (which are required to be protected with either bars, expanded metal grills, commercial metal sounds baffles) to ensure they are properly secured.  Additionally all traversable space surrounding the exterior of the Secure Room must be viewed by the checker by walking around the entire perimeter.  

5.  Checks must be supported by written procedures/instructions for the checkers and results of checks must be recorded.  

6. Locally developed checklists or the Standard Form (SF) 701 must be used to document checks.  Completed checklists should be maintained on-hand for at least 90-days as an audit trail or indefinitely if discrepancies were noted during any checks.

It is important to note that random checks are an allowable alternative to IDS *ONLY* if supported by a valid risk assessment AND security-in-depth countermeasures as determined in writing by the CC/S/A senior agency official (SAO)(INFOSEC).  Not meeting this requirement will result in a finding.  

Use of IDS and risk analysis are each covered as separate checks elsewhere in this document.   

This particular requirement (random checks of secure rooms) is Not Applicable (NA) if IDS is used.  

In summary this requirement is intended to implement and validate that random checks not exceeding 4-hours are being used AND that it is supported by a valid risk assessment along with security-in-depth countermeasures.'
  impact 0.7
  ref 'DPMS Target Traditional Security Checklist'
  tag check_id: 'C-49235r770072_chk'
  tag severity: 'high'
  tag gid: 'V-245804'
  tag rid: 'SV-245804r770314_rule'
  tag stig_id: 'IS-02.01.10'
  tag gtitle: 'IS-02.01.10'
  tag fix_id: 'F-49190r770073_fix'
  tag 'documentable'
  tag legacy: ['SV-41545r3_rule', 'V-31278']
end
