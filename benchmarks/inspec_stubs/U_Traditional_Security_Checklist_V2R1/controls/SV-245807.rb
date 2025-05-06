control 'SV-245807' do
  title 'Information Security (IS) - Continuous Operations Facility: Access Control Monitoring Methods'
  desc 'Failure to control door access to a Continuous Operations Facility containing classified SIPRNET assets may result in immediate and potentially undetected access to classified information, with no capability to immediately alert response forces.  Ultimately this could result in the undetected loss or compromise of classified material.

USE CASE EXPLANATION:

A Continuous Operations Facility functions 24/7 and contains classified SIPRNet equipment and/or media.  It often does not meet all the physical and/or procedural requirements of a vault or secure room (AKA: collateral classified open storage area) and the classified equipment and/or media may not be stored in an approved safe when not in use.  Examples of such facilities are Emergency Operations Centers (EOC), Information System Monitoring Centers, Trouble Desk Centers, etc.  All standards for access control monitoring for Continuous Operations Facilities are found in the DoD Manual 5200.01, V3 and this STIG Requirement/Rule provides additional clarification and implementation standards for all Continuous Operations Facilities containing SIPRNet assets.

Continuous Operations Facilities are not routinely closed and secured after normal business hours and reopened at the beginning of normal workdays.   A CONTINUOUS OPERATIONS FACILITY MUST BE CONTINUOUSLY OCCUPIED at all times, OR IT MUST MEET ALL PHYSICAL STRUCTURAL AND PROCEDURAL STANDARDS FOR A SECURE ROOM AND BE SECURED (*using an approved FF-L-2740 combination lock) DURING PERIODS WHEN IT IS NOT OCCUPIED.  It is not necessary to activate the supplemental controls (IDS or 4-hour checks) when securing the facility using the FF-L-2740 lock during working hours. However, this must be done if the facility is formally closed at any time and will include End-of-Day (EOD) checks.   A "facility" can be a single room or a larger contiguous area, often (but not always) without Federal Specification FF-L-2740 combination locks on the primary access door.  Continuous Operations area access control procedures must meet the requirements herein even where the surrounding area is continuously occupied.  Continuous Operations (again - continuous occupancy)  minimizes or eliminates the need for/use of certain security measures such as FF-L-2740 combination locks, standard door locks, IDS, 4-hour guard checks, etc.

Where there is a Continuous Operations Facility there should be demonstrated mission need for continuous occupation of the "specific" room or area containing the classified SIPRNet assets.  A justification that the surrounding building or facility is continuously occupied is not acceptable.  If this is observed, reviewers should consider the possibility that the stated requirement for a Continuous Operations Facility is being used to cover deficiencies with what should legitimately be established as a secure room or vault.  In such cases the use of Traditional Security STIG Requirements and applicable physical and procedural standards for vaults and/or secure rooms may be more appropriate, resulting in findings under those Requirements.

A Continuous Operations Facility containing classified materials is most appropriate when it is continuously occupied by properly cleared employees (or others with security clearance and a need-to-know) who are capable of controlling or monitoring ingress and egress from within the area.  This provides the most legitimate justification for using a Continuous Operations Facility vice using a properly constructed and access controlled vault or secure room (AKA: collateral classified open storage area).  Convenience and ease of access is not proper justification for a Continuous Operations Facility.

Continuous Operations Facility door control may be accomplished multiple ways.  There are five main types of access control methods listed below.  One or more of the five methods may apply to any facility.  Each access point must comply with one or more of the methods of access control for 24 hours of each operational day.  Any deficiency for any facility access point (even for a portion of the day for an access point) will result in a finding under this STIG rule.  All Continuous Operations Facilities access points should be checked for proper access control according to the type of access control method(s) implemented.

Direct access control monitoring for both occupied and unoccupied Continuous Operations Facilities is conducted by:  cleared employees, guards or receptionists located inside the area or directly outside the area.  A properly configured Automated Entry Control System (AECS) or continuously monitored Closed Circuit Television (CCTV) are the only options for indirect monitoring of Continuous Operations Facilities.

The five basic methods for controlling access to Continuous Operations Facilities are:

1.  Method #1: Use of an Automated Entry Control System (AECS) Card Reader with Biometrics or Personal Identification Number (PIN)

2.  Method #2:  Access Continually Monitored by Occupants (Cleared Employees) of the Continuous Operations Facility - all doors NOT visible

3.  Method #3:  Access Monitored by Occupants (Cleared Employees) of the Continuous Operations Facility - all doors are visible

4.  Method #4:  Access Monitored by Employees Directly Outside the Open Storage Space - all doors MUST BE visible

5.  Method #5:  Access Monitored by Closed Circuit Television (CCTV) reporting to a Central Monitoring Station Staffed 24/7 by cleared Guards or Other cleared Security Professionals - each individual door MUST HAVE a CCTV camera(s)

Normally only one method of access control will be applicable to a specific Continuous Operations Facility; however, there may be situations where more than one approved method is being used at a single facility.  For instance an Automated Entry Control System (AECS) with card reader and PIN may be used to secure the access door while there are also employees located inside the room who can monitor and control access.  In situations where multiple methods are found, reviewers need only choose one of the five to evaluate compliance and its effectiveness of access control to the Continuous Operations Facility.  If one of the methods is found to be totally compliant while others in use contain deficiencies, the method that is 100% compliant should be selected for use during the review.  In the example just provided, if the room is only occupied by one employee who is monitoring access and during breaks or for other reasons exits the room for periods of time this would cause a significant deficient condition since the access door is not continuously monitored by the employee.  Therefore using the AECS as the method to evaluate access control for the Continuous Operations Facility would likely be selected since it appears to be (and for this example we will assume) 100% compliant.

There is also a possibility that multiple Continuous Operations Facilities could be found at a particular site location (even in the same building) that are using different methods to control access.  Once again, multiple methods of access control from the list of five could be selected for the evaluation, based on the access control methods actually being used for the various 24/7Continuous Operations Facilities.

Once the applicable Continuous Operations Facility access control methods that apply to each of the Continuous Operations Facilities at the site are selected, the site must comply with all of the individual checks for the selected method(s).  Specific checks for requirements associated with a method of access control are found in the Check Content information field.

If there is no Continuous Operations Facility at a particular site this Requirement is Not Applicable (NA) for a review.

REFERENCES:

The Information Security Oversight Office (ISOO): http://www.archives.gov/isoo/   Implementing Directive for Protection of Classified (for Executive Order 13526), 32 CFR Parts 2001 and 2003 Classified National Security Information: paragraph 2001.43 Storage, (2) Secret.

CJCSI 6510.01F, INFORMATION ASSURANCE (IA) AND SUPPORT TO COMPUTER NETWORK DEFENSE (CND), Enclosure C, paragraphs 24.j. and 34.

NIST Special Publication 800-53 (SP 800-53), Rev 4, Controls: MP-4, PE-2, PE-3, PE-5 and PE-6

DoD Manual 5200.01, Volume 3, SUBJECT: DoD Information Security Program: Protection of Classified Information: Specific paragraph references are individually annotated with each specific check - under the "Checks" section.

DoD 5200.22-M (NISPOM), Incorporating Change 2, 18 May 2016, paragraphs 5-306, 5-312, 5-313, 5-314'
  desc 'check', 'Unless otherwise indicated all the paragraph citations preceding each check are from DoD Manual 5200.01, Volume 3, 24 February 2012, SUBJECT: DoD Information Security Program: Protection of Classified Information.

The following set of 5 checks for Continuous Operations Access Control Monitoring Method #1 is to be used when an Automated Entry Control System (AECS) Card Reader with Biometrics or Personal Identification Number (PIN) is the primary means of access control to the Continuous Operations Facility:

Method 1/Check #1.  Appendix to Enclosure 3, para 3.a.(2)(a); para 3.a.(2)(b); para 3.a.(3); para 3.a.(4) -- Check to ensure an Automated Entry Control System (AECS) is used that incorporates a coded ID card or badge PLUS either a PIN or Biometrics on both the primary entrance and all secondary doors that may be used for continuous or intermittent access to the secure room space.  (CAT I)

Method 1/Check #2.  Appendix to Enclosure 3, para 2.d.(6); para 2.f.(2)& para 3.a. -- Check to ensure the AECS is controlled and monitored at a continuously manned central monitoring station. (CAT I)

Method 1/Check #3.  Enclosure 3, para 3 & para 12; Appendix to Enclosure 3, para 2.e(6); Enclosure 2, para 2; -- If there is no IDS employed (*which must be based on a documented risk assessment) on doors or other man-passable openings: Check to ensure the 24/7 secure rooms or collateral secret open storage areas (containing SIPRNet equipment) are continuously occupied by at least one properly cleared employee. (CAT I)

Method 1/Check #4.  Appendix to Enclosure 3, para 2.e(6) -- If there is no Intrusion Detection System (IDS) employed in the Continuous Operations Facility:  Check to ensure that a duress device is available for occupants inside the facility, IF DETERMINED NECESSARY BY A DOCUMENTED RISK ASSESSMENT (RA).  If there is no duress device and no RA to validate that there is no need for duress, it is a finding. (CAT II)

Method 1/Check #5.  Enclosure 3, para 3.b.(3)(a) & (b)-- Where there is no IDS employed in the Continuous Operations Facility and ALL classified (SIPRNet) equipment, devices and media are not under the direct  continuous observation and control of area occupants (CLEARED EMPLOYEES):  Check to ensure a system of checks of classified assets (especially SIPRNet connected assets) internal to the Continuous Operations Facility, not exceeding 4 hours is established and conducted. (CAT I)

XXXXXXXXXXXXXXXXXXXXXXXXXXXXXX

The following set of 6 checks for Continuous Operations Access Control Monitoring Method #2  is to be used Access is Continuously Monitored by Occupants (Cleared Employees) of the Continuous Operations Facility - all doors are NOT visible - is the primary means of access control to the Continuous Operations Facility:

Method 2/Check #1.  Appendix to Enclosure 3, para 2.e(6) - When cleared occupants cannot directly and continuously observe all potential entrances into the room, check to ensure an open door alerting system is used to alert occupants of the 24/7 continuous operations. The alerting system MUST cover all access points that cannot be observed by occupants including the primary entrance and all secondary doors that could be used for continuous or intermittent access. (CAT I)

Method 2/Check #2.  Enclosure 3, para 3 & para 12; Appendix to Enclosure 3, para 2.e(6); Enclosure 2, para 2 -- Check to ensure the 24/7 Continuous Operations Facility is "continuously occupied" by at least one properly cleared employee. (CAT I)

Method 2/Check #3.  Appendix to Enclosure 3, para 3.a.(2)(a); para 3.a.(2)(b); para 3.a.(3); para 3.a.(4)-- On those doors not visible to cleared occupants: Check to ensure that an Automated Entry Control System (AECS) is used that incorporates both a coded ID card or badge plus either a PIN or Biometrics.  This requirement is for all doors that are not continuously visible including the primary entrance and all secondary doors that may be used for continuous or intermittent access.  (CAT I)

Method 2/Check #4.  Appendix to Enclosure 3, para 3.a. & para 3.c. -- Check to ensure doors that are continuously visible to cleared occupants are access controlled minimally by either an AECS using swipe or proximity cards (*not required to have PIN or biometric verification) OR by Electric, Mechanical, or Electromechanical Access Control Devices IAW the specifications of DoD Manual 5200.01, Volume 3, Appendix to Enclosure 3, para 3.c...  (CAT I)

Method 2/Check #5.  Appendix to Enclosure 3, para 2.e(6) -- If there is no IDS employed in the Continuous Operations Facility:  Check to ensure that a duress device is available for occupants inside the facility, IF DETERMINED NECESSARY BY A DOCUMENTED RISK ASSESSMENT (RA).  If there is no duress device and no RA to validate that there is no need for duress, it is a finding. (CAT II)

Method 2/Check #6.  Enclosure 3, para 3.b.(3)(a) & (b) -- Where there is no IDS employed in the Continuous Operations Facility and ALL classified (SIPRNet) equipment, devices and media are not under the direct  continuous observation and control of area occupants (CLEARED EMPLOYEES): Check to ensure a system of checks of classified assets (especially SIPRNet connected assets) internal to the Continuous Operations Facility, not exceeding 4 hours is established and conducted. (CAT I)

XXXXXXXXXXXXXXXXXXXX

The following set of 5 checks for Continuous Operations Access Control Monitoring Method #3  is to be used when Access is Monitored by Occupants (Cleared Employees) of the Continuous Operations Facility and all doors are visible - is the primary means of access control to the Continuous Operations Facility:

Method 3/Check #1. Enclosure 3, para 12; Appendix to Enclosure 3, para 3.a -- Check to ensure that cleared employees who work in the space just inside the Continuous Operations Facility have continuous visual observation of all primary entrance and all secondary doors that may be used for continuous or intermittent access. (CAT I)

Method 3/Check #2. Enclosure 3, para 3 & para 12; Appendix to Enclosure 3, para 2.e(6); Enclosure 2, para 2; -- -- Check to ensure the 24/7 Continuous Operations Facility is "continuously occupied" by at least one properly cleared employee. (CAT I)

Method 3/Check #3. Appendix to Enclosure 3, para 3.a. & para 3.c. -- Check to ensure doors that are continuously visible to cleared occupants are access controlled minimally by either an AECS using swipe or proximity cards (*not required to have PIN or biometric verification) OR by Electric, Mechanical, or Electromechanical Access Control Devices IAW the specifications of DoD Manual 5200.01, Volume 3, Appendix to Enclosure 3, para 3.c...  (CAT I)

Method 3/Check #4. Appendix to Enclosure 3, para 2.e(6)-- If there is no IDS employed in the Continuous Operations Facility:  Check to ensure that a duress device is available for occupants inside the facility, IF DETERMINED NECESSARY BY A DOCUMENTED RISK ASSESSMENT (RA).  If there is no duress device and no RA to validate that there is no need for duress, it is a finding. (CAT II)

Method 3/Check #5. Enclosure 3, para 3.b.(3)(a) & (b) -- Where there is no IDS employed in the Continuous Operations Facility and ALL classified (SIPRNet) equipment, devices and media are not under the direct  continuous observation and control of area occupants (CLEARED EMPLOYEES):  Check to ensure a system of checks of classified assets (especially SIPRNet connected assets) internal to the Continuous Operations Facility, not exceeding 4 hours is established and conducted. (CAT I)

XXXXXXXXXXXXXXXXXXX

The following set of 5 checks for Continuous Operations Access Control Monitoring Method #4 is to be used when Access is Monitored by Cleared Employees Directly Outside the Continuous Operations Facility - all doors MUST BE visible - is the primary means of access control to the Continuous Operations Facility:

Method 4/Check #1.  Appendix to Enclosure 3, para 3.a. - Check to ensure that cleared employees who work in the space just outside the Continuous Operations Facility (containing SIPRNet equipment) are providing continuous visual observation of the primary entrance and all secondary doors that may be used for continuous or intermittent access. They must be continuously present with no gaps in coverage. (CAT I)

Method 4/Check #2. Appendix to Enclosure 3, para 3.a. - Check to ensure that cleared employees working outside the Continuous Operations Facility are located directly adjacent to a particular door or set of doors being monitored and are informed concerning their specific responsibilities for monitoring door security/access control. Written procedures must be available to substantiate this. (CAT II)

Method 4/Check #3. Appendix to Enclosure 3, para 3.a. & para 3.c.-- Check to ensure doors that are continuously visible and controlled by cleared employees directly outside the Continuous Operations Facility are access controlled minimally by either an AECS using swipe or proximity cards (*not required to have PIN or biometric verification) OR by Electric, Mechanical, or Electromechanical Access Control Devices IAW the specifications of DoD Manual 5200.01, Volume 3, Appendix to Enclosure 3, para 3.c... (CAT I)

Method 4/Check #4.  Appendix to Enclosure 3, para 2.e(6) - If there is no IDS employed in the Continuous Operations Facility:  Check to ensure that a duress device is available for cleared employees monitoring door access from outside the facility, IF DETERMINED NECESSARY BY A DOCUMENTED RISK ASSESSMENT (RA).  If there is no duress device and no RA to validate that there is no need for duress, it is a finding. (CAT II)

Method 4/Check #5.  Enclosure 3, para 3.b.(3)(a) & (b) -- Where there is no IDS employed in the Continuous Operations Facility and ALL classified (SIPRNet) equipment, devices and media are not under the direct continuous observation and control of occupants within the facility (CLEARED EMPLOYEES):  Check to ensure a system of checks of classified assets (especially SIPRNet connected assets) internal to the Continuous Operations Facility, not exceeding 4 hours is established and conducted. (CAT I)

XXXXXXXXXXXXXXXXXXX

The following set of 6 checks for Continuous Operations Access Control Monitoring Method #5 is to be used when Access is Monitored by Closed Circuit Television (CCTV) reporting to a Central Monitoring Station Staffed 24/7 by cleared Guards or Other cleared Security Professionals - all doors MUST HAVE CCTV cameras - is the primary means of access control to the Continuous Operations Facility:

Method 5/Check #1. Enclosure 3, para 12; Appendix to Enclosure 3, para 3.a.; para 2.d.(6)& para 2.f.(2) - Check to ensure ALL doors (primary and secondary) are actively monitored via CCTV by cleared guards at a central monitoring facility. (CAT I)

Method 5/Check #2.  Appendix to Enclosure 3, 3.a.(7) - Check to ensure that CCTV activity is recorded and maintained on file for a minimum of 90 days. (CAT II)

Method 5/Check #3.  Enclosure 3, para 12; Appendix to Enclosure 3, para 3.a. & para 2.f.(2) - Check to ensure that guards are continuously present at the monitoring location and  informed concerning their specific responsibilities for monitoring and responding to potential unauthorized attempts to breach the Continuous Operations Facility. Written procedures must be available.  (CAT I)

Method 5/Check #4. Enclosure 3, para 3 & para 12; Appendix to Enclosure 3, para 2.e(6); Enclosure 2, para 2; - Check to ensure the 24/7 Continuous Operations Facilities are continuously occupied by at least one properly cleared employee. (CAT I)

Method 5/Check #5. Appendix to Enclosure 3, para 3.a. & para 3.c. -- Check to ensure doors that are continuously visible and controlled by CCTV from directly outside the Continuous Operations Facility are access controlled minimally by either an AECS using swipe or proximity cards (*not required to have PIN or biometric verification) OR by Electric, Mechanical, or Electromechanical Access Control Devices IAW the specifications of DoD Manual 5200.01, Volume 3, Appendix to Enclosure 3, para 3.c... (CAT I)

Method 5/Check #6. Enclosure 3, para 3.b.(3)(a) & (b) -- Where there is no IDS employed in the Continuous Operations Facility and ALL classified (SIPRNet) equipment, devices and media are not under the direct continuous observation and control of occupants within the facility (CLEARED EMPLOYEES):  Check to ensure a system of checks of classified assets (especially SIPRNet connected assets) internal to the Continuous Operations Facility, not exceeding 4 hours is established and conducted. (CAT I)

TACTICAL ENVIRONMENT:  The 5 sets of monitoring methods and associated checks are applicable where Continuous Operations Facilities are used to protect classified materials or systems in a tactical environment. The only exception will be for urgent (short term) tactical operations or other contingency situations where fixed facilities and equipment are not yet present or incapable of being used.'
  desc 'fix', 'Continuous Operations Facilities storing classified SIPRNet assets in the open are not routinely opened or closed using Federal Specification FF-L-2740 combination locks due to being continuously occupied by cleared employees or due to very frequent access requirements for operational reasons.

As applicable to the operating environment at a particular site/location, select one or more of the five Methods of Access Control to be used for 24/7 Continuous Operations Facilities.  The five methods of access control along with specific requirements/checks are found in the Check Content of this Requirement.

More than one method of access control might apply to a particular Continuous Operations Facility or to multiple Continuous Operations Facilities at a single site/location.  

Based on the access control method(s) used for each individual Continuous Operations Facility at a site, comply with all of the requirements detailed in all of the individual checks applicable to the selected method(s) of access control. Compliance with at least one complete set of checks applicable to a particular method of access control is required for each Continuous Operations Facility.'
  impact 0.7
  ref 'DPMS Target Traditional Security Checklist'
  tag check_id: 'C-49238r770315_chk'
  tag severity: 'high'
  tag gid: 'V-245807'
  tag rid: 'SV-245807r770316_rule'
  tag stig_id: 'IS-02.01.13'
  tag gtitle: 'IS-02.01.13'
  tag fix_id: 'F-49193r770082_fix'
  tag 'documentable'
  tag legacy: ['SV-41565r3_rule', 'V-31294']
end
