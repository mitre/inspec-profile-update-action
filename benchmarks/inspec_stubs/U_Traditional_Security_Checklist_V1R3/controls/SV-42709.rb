control 'SV-42709' do
  title 'Information Assurance (IA) Positions of Trust - Identification of Positions or Duties with Privileged Access to Information Systems or Responsibility for Security Oversight of Information Systems'
  desc %q(RULE OVERVIEW:
Failure to identify Information Assurance (IA) Positions of Trust could result in an incumbent of such position having Privileged Access to, or Security Oversight of an information system without the required investigative and adjudicative prerequisites.

Information Assurance (IA) Positions of Trust are specifically those positions with Privileged Access to an Information System(s) or positions with responsibility for Oversight of Systems Security.   Examples are System Administrators (SA), Information System Security Managers (ISSM), Information System Security Officers (ISSO), Information System Engineers, System Designers…

Formerly Information Assurance (IA) Positions of Trust were identified under the Automated Data Processing (ADP) (AKA: Information Technology (IT)) Position Categories and Criteria IAW the DoD 5200.2-R, Personnel Security Program, January 1987.  These long established legacy ADP Categories were not included in the update to the DOD PERSEC Program contained in the DOD Manual 5200.02, Procedures for the DoD Personnel Security Program (PSP), dated 3 April 2017.

This possible gap in policy guidance has been addressed with the USD(I) PERSEC Policy authority and they are aware of the omission of the guidance in the PERSEC update.

Pending further direction from the USD(I) their guidance is to use the Office of Personnel Management (OPM) Position Designation Tool (PDT).

Because many organizations have institutionalized the ADP Categories and Criteria, the use of the legacy ADP position methodology for identification and designation of position sensitivity for IT Positions of Trust may still be used in lieu of the PDT for compliance with requirements in this STIG Rule. 
 
LEGACY ADP CRITERIA EXPLAINED:
With regard to the former ADP/IT level designations the following general rules apply:

Critical-Sensitive Positions
ADP-I positions. Those positions in which the incumbent is responsible for the planning, direction, and implementation of a computer security program; major responsibility for the direction, planning and design of a computer system, including the hardware and software; or, can access a system during the operation or maintenance in such a way, and with a relatively high risk for causing grave damage, or realize a significant personal gain (e.g., privileged access and/or systems security oversight).

Noncritical-Sensitive Positions
ADP-II positions. Those positions in which the incumbent is responsible for the-direction, planning, design, operation, or maintenance of a computer system, and whose work is technically reviewed by a higher authority of the ADP-I category to insure the integrity of the system.

Non-sensitive Positions
ADP-III positions. All other positions involved in computer activities. In establishing the categories of positions, other factors may enter into the determination, permitting placement in higher or lower categories based on the Agency's judgement as to the unique characteristics of the system or the safeguards protecting the system.

RELEVANT BACKGROUND INFORMATION:
All positions (military and civilian) must be categorized as either special-sensitive, critical-sensitive, noncritical-sensitive or non-sensitive based on a variety of duties associated with a specific position.

Two of the most prevalent criteria used within the DoD for determination of position sensitivity are the level of security clearance (e.g., TS, S, C) and/or the level of access granted to information technology (IT) systems (e.g., privileged access (AKA: system administrator (SA)) or non-privileged access (AKA: authorized user access)).

The significance of designating position sensitivity is the type of background investigation the incumbent of a particular position must undergo (e.g., Tier 5 investigation (formerly SSBI) or Tier 3 investigation (formerly NACI/ANACI)) is based upon the designated position sensitivity.

FOLLOWING ARE A SUMMARY OF CHANGES TO:

1. TYPES OF INVESTIGATIONS AND 
2. AUTOMATED DATA PROCESSING (ADP) (AKA: INFORMATION TECHNOLOGY (IT)) POSITION CATEGORIES:

As of 1 October 2016, the former investigations known as NACLAC, ANACI, NACI, BI, MBI, SSBI, etc. are no longer conducted.  These investigations have been replaced by the Office of Personnel Management (OPM) with a "Tiered" Investigation process.

The new investigations are grouped in five levels or tiers and investigations are now referred to as Tier 1-5, with Tier 5 (T-5) being the most stringent investigation and Tier 1 (T-1) being the least stringent.

The update to the DOD PERSEC Program contained in the DOD Manual 5200.02, Procedures for the DoD Personnel Security Program (PSP), dated 3 April 2017 does not contain any implementing guidance for moving from the former investigations to the new Tiered Investigations.

As previously mentioned, the update to the DOD PERSEC Program also does not include Automated Data Processing (ADP) (AKA: Information Technology (IT)) Position of Trust categories used for designation of position sensitivity IAW the former DoD 5200.2-R, January 1987, which was replaced by the updated Manual.

Again, these gaps in policy guidance have been addressed with the USD(I) PERSEC Policy authority and they are aware of the omission of the guidance in the PERSEC update.

POSITION DESIGNATION TOOL (PDT):  
Both of the policy gaps may or may not be addressed in the next PERSEC Manual update but pending formal documented guidance the USD(I) has provided verbal/email guidance to the DISA Traditional Security STIG SME to direct DoD users to use the Office of Personnel Management (OPM) Position Designation Tool (PDT).  Position Designation Tool URL:

https://www.opm.gov/suitability/suitability-executive-agent/position-designation-tool/
  
The PDT contains Information Technology (IT) Position criterial similar to the former ADP criteria.  Proper input of IT position responsibility criteria into the PDT will calculate and provide both a position sensitivity designation and the associated background investigation requirement.

Use of the PDT will provide essentially the same outcome as the guidance using former ADP designations (e.g., position sensitivity designation and type of background investigation required).  This assertion assumes job related IT criteria are correctly input into the PDT.
 
It is important to understand the DoD position sensitivity designations as detailed in the Personnel Security Program (PERSEC) Manual are based primarily on designated security clearance requirements and other specified job related duties and responsibilities.  While similar, the OPM position designation system differs from the DoD PERSEC guidance.  The difference is that while the OPM Position Designation Tool (PDT) determines position sensitivity based upon security clearance requirements and/or the duties of a position (or contractually established set of duties); it also applies the estimated impact levels (e.g., high, medium and low) of these assigned duties to National Security along with calculated/assigned risk levels.  These additional “subjective” factors are key determining criteria for position sensitivity in the PDT.

To reduce subjectivity in the position sensitivity determination process security personnel must understand the following terms when using the PDT:

NATIONAL SECURITY refers to those activities which are directly concerned with the foreign relations of the United States, or protection of the Nation from internal subversion, foreign aggression, or terrorism.

A NATIONAL SECURITY POSITION, includes any position in a department or agency, the occupant of which could bring about, by virtue of the nature of the position, a material adverse effect on the national security.

NON-SENSITIVE POSITIONS/DUTIES are PUBLIC TRUST POSITIONS or duties and responsibilities that are unrelated to National Security.

*Keep in mind that the primary mission of most DoD organizations concerns the national security.  Hence all Information Technology (IT) positions involved with the DoD (DISN) cyber security mission should be considered as National Security Positions.  These positions are for instance System Administrators (SA), Information System Security Managers (ISSM), Information System Security Officers (ISSO), Information System Engineers and other related positions, which are detailed in the DoD 8570.01-M, Information Assurance Workforce Improvement Program, 19 December 2005, Incorporating Change 4, 11/10/2015.

Again, the outcome of using the PDT should generally be the same as the DoD requirements for position sensitivity under the legacy ADP/IT position criteria but the individual using the tool must have a thorough understanding of the duties and impact of the duties of each position being assessed for the PDT outcome to be appropriate and consistent with the DoD standards.  It is important to limit the subjectivity involved with these determinations and provide consistent results throughout the DoD.

PRIVILEGED ACCESS TO INFORMATION TECHNOLOGY SYSTEMS: 
A key legacy consideration for IT positions of trust is that any position where an incumbent has “Privileged Access” to an information system should normally be designated as a Critical-Sensitive position.   *This is regardless if there is a corresponding requirement for the incumbent to have a TS security clearance or not.  Generally the TS clearance is the predominate requirement for designation of position sensitivity as critical-sensitive; however, where there is a requirement for either a secret, confidential, or no security clearance and the incumbent also has a requirement for privileged access to an information system – the privileged access criterial will make the position critical-sensitive with a Tier-5 (T-5) background investigation requirement.  

Hence, the privileged access criteria consideration is beyond the typical noncritical-sensitive or non-sensitive position designations associated with only a secret, confidential, or no security clearance normally resulting in a Tier-3 (T-3) or lower level investigation requirement. 

PRIVILEGED ACCESS DEFINED:
The following definition of privileged access is excerpted from the DoD 8570.01-M, Information Assurance Workforce Improvement Program.

Privileged Access is an authorized user who has access to system control, monitoring, administration, criminal investigation, or compliance functions. Privileged access typically provides access to the following system controls:

-Access to the control functions of the information system/network, administration of user accounts, etc.

-Access to change control parameters (e.g., routing tables, path priorities, addresses) of routers, multiplexers, and other key information system/network equipment or software.

-Ability and authority to control and change program files, and other users’ access to data.

-Direct access to operating system level functions (also called unmediated access) that would permit system controls to be bypassed or changed.

-Access and authority for installing, configuring, monitoring, or troubleshooting the security monitoring functions of information systems/networks (e.g., network/system analyzers; intrusion detection software; firewalls) or in performance of cyber/network defense operations.
************end of Privileged Access Definition*********

CONNECTION OF TIER 3 (T-3) AND TIER 5 (T-5) INVESTIGATIONS TO IT POSITIONS OF TRUST AND SECURITY CLEARANCES:

With regard to Information Technology (IT) positions of trust for protection of DoD Information Network (DoDIN) (AKA: Defense Information System Network (DISN)) assets, the two most applicable levels of investigation are Tier 3 and Tier 5.

Tier 3 investigations are those generally associated with Non-Critical Sensitive positions of trust (confidential or secret security clearance or former ADP II level duties).  Examples of the former investigations which are now Tier 3 are NACLAC and ANACI.
 
Tier 5 investigations are those generally associated with Special-Sensitive and/or Critical Sensitive positions of trust (TS clearances with or w/o SCI/SAP or Privileged Access to IT / former ADP I level duties).  The former investigation that is now Tier 5 is the SSBI.

In the next several years it is reasonable to expect that a combination of both the old investigations and the new Tier investigations will be found within the DoD until the new investigations are completely phased-in for current personnel.  Therefore, security managers must continue to be familiar with both the old and new investigations.

CONTRACTOR PERSONNEL AND IT POSITIONS OF TRUST:
While Contractor personnel are not formally assigned to positions within DoD organizations, the type of investigation required is like DoD civilians and military personnel in that it is based on security clearance requirements for each type or category of work performed and IT system access levels.  Specific IT system duties/access levels along with security clearance requirements and associated investigations must be detailed in the applicable Statement of Work and/or DD Form 254 (Contract Security Specification).  

THE BOTTOM LINE:
In summary the association of DoD position sensitivity designation and required investigations is based on IT position of trust system access levels and/or level of responsibility for oversight of systems security  in conjunction with the level of security clearance required for military or civilian positions *or type of work performed by contractor employees.  The relationship of position sensitivity to clearances, duties and investigations can be delineated as follows:

*Special-Sensitive and/or Critical- Sensitive positions:  
   Legacy IT-1 (ADP-1)
   Privileged users (SAs) and/or
   ISSM/ISSO and/or 
   TS or TS-SCI clearance
   SSBI/Tier 5 investigations

**Non-Critical Sensitive positions:  
    Legacy IT-2 (ADP-2)
    Privileged users under direct supervision of an ADP-1 vetted Privileged user and/or
    Authorized users and/or 
    Confidential or secret security clearance 
    NACLAC, ANACI, NACI/Tier 3 investigations

***Non-Sensitive positions:
      Legacy IT-3 (ADP-3) and no security clearance; Not Applicable for current DoD cyber security positions

REFERENCES:

DoDI 8500.01, March 14, 2014, SUBJECT: Cybersecurity: Paragraph 10.a-e (Cybersecurity Workforce)

DoD 8570.01-M, Information Assurance Workforce Improvement Program, 19 December 2005, Incorporating Change 4, 11/10/2015: Paragraphs C1.4.4.4., C1.4.4.5., C3.2.4.1.2., C3.2.4.2., C3.2.4.8., C4.2.3.1.2., AP1.15 and AP 1.22.

CJCSI 6510.01F, INFORMATION ASSURANCE (IA) AND SUPPORT TO COMPUTER NETWORK DEFENSE (CND); Enclosure A, paragraphs 7 and 11., Enclosure B, paragraph 2.l. and Enclosure C, paragraph 4. and paragraph 10.

NIST Special Publication 800-53 (SP 800-53), Rev 4, Controls: PE-2(1), PS-1, PS-2, PS-3, PS-6(1) and PS-6(2).

DoD 5200.22-M (NISPOM), Incorporating Change 2, 18 May 2016, Chapter 2, Section 2 and Chapter 8, Section 3, paragraph 8-302.a. Personnel Security.

(Current) DoD Manual 5200.02, Procedures for the DoD Personnel Security Program (PSP), April 3, 2017, Paragraphs 4.1.a.(2)(m), (r), (u) & (3)(a), (b), (c) and 4.1.b. Civilian Personnel, 4.2. Military Personnel, 4.3. Contractors, 4.4. Consultants.

(Legacy) DoD 5200.2-R, Personnel Security Program, Chapter 3, paragraphs C3.1., C3.1.2.1.1.7., C3.1.2.1.2.3., C3.1.3., C.3.2, C3.3 and C3.6.15, and Appendix 10.

OPM/National Background Investigations Bureau URL:

https://www.opm.gov/suitability/

https://nbib.opm.gov/

https://nbib.opm.gov/hr-security-personnel/requesting-opm-personnel-investigations/#url=5.0

*POSITION DESIGNATION TOOL:
https://www.opm.gov/suitability/suitability-executive-agent/position-designation-tool/

The Joint Personnel Adjudication System (JPAS) and the Defense Information System for Security (DISS).  Once fully deployed, DISS will replace JPAS to serve as the system of record to perform comprehensive personnel security, suitability and credential eligibility management for all military, civilian, and DOD contractor personnel.  These databases reflect position sensitivity, security clearance information and ADP/IT information for vetted individuals.)
  desc 'check', 'Check to ensure that positions identified under STIG Rule: PE-02.02.01, Position Sensitivity - that have Privileged Access or Responsibility for Oversight of Systems Security (e.g., System Administrators, ISSM or ISSO) on DoDIN systems *are in positions identified as Critical-Sensitive.  This result may be established and/or validated using the legacy ADP Position Criteria (ADP-1 in this instance) or by using the OPM Position Designation Tool (PDT).  

This is required for members of the DoD workforce conducting Cyber Security (AKA: Information Assurance (IA)) functions in assigned duty positions.  Examples include but are not limited to: Information System Security Manager (ISSM), Information System Security Officer (ISSO), and System Administrator (SA).  These are positions consistent with the IA Workforce Improvement Program (DoD 8570.01-M) that are required to be trained, certified and specially vetted for integrity and loyalty. 

NOTE 1:  Information Assurance (IA) Positions of Trust are specifically those positions with Privileged Access to an Information System(s) or positions with responsibility for Oversight of Systems Security.   Examples are System Administrators (SA), Information System Security Managers (ISSM), Information System Security Officers (ISSO), Information System Engineers, System Designers…

NOTE 2:  Formerly Information Assurance (IA) Positions of Trust were identified under the Automated Data Processing (ADP) (AKA: Information Technology (IT)) Position Categories and Criteria IAW the DoD 5200.2-R, Personnel Security Program, January 1987.  These long established legacy ADP Categories were not included in the update to the DOD PERSEC Program contained in the DOD Manual 5200.02, Procedures for the DoD Personnel Security Program (PSP), dated 3 April 2017.

NOTE 3:  Because many organizations have institutionalized the ADP Categories and Criteria, the use of this legacy methodology for identification and designation of position sensitivity for IT Positions of Trust may still be used in lieu of the OPM Position Designation Tool (PDT) for compliance with requirements in this STIG Rule. 

NOTE 4: Personnel Occupying Information Assurance (IA) Positions of Trust under the legacy program are designated ADP-1, ADP-2 and ADP-3. DoD military, civilian personnel, consultants, and contractor personnel performing on unclassified automated information systems may be assigned to one of three position sensitivity designations (in accordance with Appendix 10 of the legacy DoD 5200.2-R, Personnel Security Program) and MINIMALLY investigated as follows:

ADP-I (AKA: IT-1): SSBI/SBPR/PPR/ T5 – Tier 5/T5R – Tier 5 Reinvestigation

ADP-II (AKA: IT-2): ANACI /NACI /NACLC/ S-PR/ T3 - Tier 3/T3R - Tier 3 Reinvestigation

ADP-III (AKA: IT-3): NAC/ENTNAC/ T1 – Tier 1/T2S  – Tier 2 with Subject Interview/T2RS - Tier 2 Reinvestigation with Subject Interview.  Note that ADP-III/IT-3 positions are all authorized (basic/routine) system users who are not in designated IA positions under the IA Workforce Improvement Program (e.g., not having privileged access or responsibility for systems security oversight).

Those personnel falling in the above ADP categories who also require access to classified information will, of course, be subject to the appropriate investigative scope for the level of security clearance required.  The investigative scope for clearances may exceed but not be less than that required for the designated ADP level.
  
NOTE 5:  Privileged access typically provides access to the following system controls IAW Change 4, APPENDIX 1 of the  DoD 8570.01-M: 
-	Access to the control functions of the information system/network, administration of user accounts, etc. 
-	Access to change control parameters (e.g., routing tables, path priorities, addresses) of routers, multiplexers, and other key information system/network equipment or software. 
-	Ability and authority to control and change program files, and other users’ access to data. 
-	Direct access to operating system level functions (also called unmediated access) that would permit system controls to be bypassed or changed. 
-	 Access and authority for installing, configuring, monitoring, or troubleshooting the security monitoring functions of information systems/networks (e.g., network/system analyzers; intrusion detection software; firewalls) or in performance of cyber/network defense operations.

NOTE 6: Certain employees with very limited AND "supervised" privileged access on information systems may be in positions designated as IT-2. Documented procedures must be available for how IT-2 privileged access is checked/supervised by IT-1 privileged access persons.  For instance regular review of system audit logs would be a normal part of the supervised privileged access procedure.  Additionally, documentation reflecting actual verification/checks by IT-1 persons of work conducted by IT-2 persons must be maintained for audit purposes for at least 90-days. 
  
NOTE 7: All designated IA Positions IAW DoD 8570.01-M (IAT Levels I-III or IAM Levels I-III) must be checked by reviewers, time permitting.  Random checks of all other site personnel records should be made.
                               
TACTICAL ENVIRONMENT: The check is applicable for fixed (established) tactical processing environments and is also applicable to a field/mobile environment.'
  desc 'fix', 'Ensure that organization manning documents (e.g., JTD) and position descriptions for Military and Government Civilians and the statement of work (SOW) and/or DD 254 (Contract Security Specification) for Contractors – are available for identification of Information Assurance (IA) Positions of Trust.
  
IA (AKA: Cyber Security) Positions of Trust must be identified for each civilian and military position and/or contractor employee duties contained in statements of work for all positions or duties in which an employee has cyber security related duties (e.g., privileged access or security oversight) on a DoDIN Information System (IS) (e.g., SIPRNet or NIPRNet).  This is required for members of the DoD workforce conducting Cyber Security (AKA: Information Assurance (IA)) functions in assigned duty positions.  Examples include but are not limited to: Information System Security Manager (ISSM), Information System Security Officer (ISSO), and System Administrator (SA).  These are positions consistent with the IA Workforce Improvement Program (DoD 8570.01-M) that are required to be trained, certified and specially vetted for integrity and loyalty. 

*Ensure that positions identified within manning documents, position descriptions, and SOWs that have Privileged Access or Responsibility for Oversight of Systems Security (e.g., System Administrators, ISSM or ISSO) on DoDIN systems are in positions identified as Critical-Sensitive.  This result may be established and/or validated using the legacy ADP Position Criteria (ADP-1 in this instance) or by using the OPM Position Designation Tool (PDT).  

NOTE 1:  Information Assurance (IA) Positions of Trust are specifically those positions with Privileged Access to an Information System(s) or positions with responsibility for Oversight of Systems Security.   Examples are System Administrators (SA), Information System Security Managers (ISSM), Information System Security Officers (ISSO), Information System Engineers, System Designers…

NOTE 2:  Information Assurance (IA) Positions of Trust were identified under the Automated Data Processing (ADP) (AKA: Information Technology (IT)) Position Categories and Criteria IAW the DoD 5200.2-R, Personnel Security Program, January 1987.  These long established legacy ADP Categories were not included in the update to the DOD PERSEC Program contained in the DOD Manual 5200.02, Procedures for the DoD Personnel Security Program (PSP), dated 3 April 2017.

NOTE 3:  Because many organizations have institutionalized the ADP Categories and Criteria, the use of this legacy methodology for identification and designation of position sensitivity for IT Positions of Trust may still be used in lieu of the OPM Position Designation Tool (PDT) for compliance with requirements in this STIG Rule. 

NOTE 4: Personnel Occupying Information Assurance (IA) Positions of Trust under the legacy program are designated ADP-1, ADP-2 and ADP-3. DoD military, civilian personnel, consultants, and contractor personnel performing on unclassified automated information systems may be assigned to one of three position sensitivity designations (in accordance with Appendix 10 of the legacy DoD 5200.2-R, Personnel Security Program) and MINIMALLY investigated as follows:

ADP-I (AKA: IT-1): SSBI/SBPR/PPR/ T5 – Tier 5/T5R – Tier 5 Reinvestigation

ADP-II (AKA: IT-2): ANACI /NACI /NACLC/ S-PR/ T3 - Tier 3/T3R - Tier 3 Reinvestigation

ADP-III (AKA: IT-3): NAC/ENTNAC/ T1 – Tier 1/T2S  – Tier 2 with Subject Interview/T2RS - Tier 2 Reinvestigation with Subject Interview.  Note that ADP-III/IT-3 positions are all authorized (basic/routine) system users who are not in designated IA positions under the IA Workforce Improvement Program (e.g., not having privileged access or responsibility for systems security oversight).

Those personnel falling in the above ADP categories who also require access to classified information will, of course, be subject to the appropriate investigative scope for the level of security clearance required.  The investigative scope for clearances may exceed but not be less than that required for the designated ADP level.
  
NOTE 5:  Privileged access typically provides access to the following system controls IAW Change 4, APPENDIX 1 of the DoD 8570.01-M: 
-	Access to the control functions of the information system/network, administration of user accounts, etc. 
-	Access to change control parameters (e.g., routing tables, path priorities, addresses) of routers, multiplexers, and other key information system/network equipment or software. 
-	Ability and authority to control and change program files, and other users’ access to data. 
-	Direct access to operating system level functions (also called unmediated access) that would permit system controls to be bypassed or changed. 
-	 Access and authority for installing, configuring, monitoring, or troubleshooting the security monitoring functions of information systems/networks (e.g., network/system analyzers; intrusion detection software; firewalls) or in performance of cyber/network defense operations.

NOTE 6: Certain employees with very limited AND "supervised" privileged access on information systems may be in positions designated as IT-2. Documented procedures must be available for how IT-2 privileged access is checked/supervised by IT-1 privileged access persons.  For instance regular review of system audit logs would be a normal part of the supervised privileged access procedure.  Additionally, documentation reflecting actual verification/checks by IT-1 persons of work conducted by IT-2 persons must be maintained for audit purposes for at least 90-days.'
  impact 0.5
  ref 'DPMS Target Traditional Security'
  tag check_id: 'C-40820r15_chk'
  tag severity: 'medium'
  tag gid: 'V-32372'
  tag rid: 'SV-42709r3_rule'
  tag stig_id: 'PE-04.02.01'
  tag gtitle: 'Information Assurance Positions of Trust'
  tag fix_id: 'F-36294r6_fix'
  tag 'documentable'
  tag potential_impacts: 'Related STIG rules:
PE-02-02-01 - Position Sensitivity - Based on Security Clearance and/or Information Technology (IT) Systems Access Level or Responsibility for Security Oversight on Assigned Information Systems (IS)
PE-03.02.01 - Validation Procedures for Security Clearance Issuance (Classified Systems and/or Physical Access Granted)
PE-05.02.01 - Background Investigations
PE-06.03.01 - Periodic Reinvestigations'
end
