control 'SV-245829' do
  title 'Classified Monitors/Displays (Physical Control of Classified Monitors From Unauthorized Viewing)'
  desc 'Failure to limit access to unauthorized personnel to information displayed on classified monitors/displays can result in the loss or compromise of classified information, including NOFORN information.

REFERENCES:

National Disclosure Policy - 1 (NDP-l) 

National Security Directive 42, "National Policy for the Security of National Security Telecommunications and Information Systems" 

DODD 5230.11, Disclosure of Classified Military Information to Foreign Governments and International Organizations SPECIAL NOTE: Enclosure 3 to DODD 5230.11 establishes specific criteria for the disclosure of classified information.

Use guidance on sharing information with REL Partners on SIPRNET at http://www.ssc.smil.mil/ - follow Policy/Guidance&Documentation link and then SIPRNet Information Sharing...

DODD 5230.20; Visits, Assignments, and Exchanges of Foreign Nationals

CJCSI 6510.01F, INFORMATION ASSURANCE (IA) AND SUPPORT TO COMPUTER NETWORK DEFENSE (CND), Encl A, para 7.b.(1) & (2) and Encl C, para 27.f. and 34.

NIST Special Publication 800-53 (SP 800-53), Rev 4, Controls: 
PE-5, PE-18, PS-3(1), PS-6, PS-6(2), MA-5

DoDI 8500.01, SUBJECT: Cybersecurity, March 14, 2014 , Enclosure 3, paragraph 11.                                    

DoD Manual 5200.02, Procedures for the DoD Personnel Security Program (PSP), 3 April 2017, Section 6., paragraphs 6.1. and 6.2.b.&c.

Originating DoD Manual 5200.01, Volume 1, SUBJECT: DoD Information Security Program: Overview, Classification, and Declassification, Encl 2, para 9.j.(1) and Encl 3,  para 5.b., 7.b.(5), 12.e.

DoD Manual 5200.01, Volume 2, 24 February 2012, SUBJECT: DoD Information Security Program: Marking of Classified Information; Enclosure 3, paragraph 18.a.

DoD Manual 5200.01, Volume 3, SUBJECT: DoD Information Security Program: Protection of Classified Information, Encl 2, para 14.a & b.;Encl 3, para 5; Encl 4, para 2.c. ;Appendix to Encl 4, para 1.f. and Encl 7.

DoD 5200.22-M (NISPOM), Incorporating Change 2, 18 May 2016, Chapter 8, Section 3, paragraphs 8-302.b.(1), 8-302.e., 8-302.g.(2), Chapter 10, Section 5 and definition of "Escort" on page C-3.'
  desc 'check', %q(BACKGROUND NOTE:  This requirement includes both situations where there is primarily a US Classified processing environment (no routine Foreign National (FN) presence) AND also contains guidance to be used for environments where FN are employed or present. It is arranged first by GUIDELINES FOR SITES WITHOUT A FN PRESENCE followed by GUIDELINES FOR ENVIRONMENTS WITH FN PRESENCE.
  
Following a lengthy discussion of the guidelines and considerations, the specific checks for this requirement are found, along with the default severity level applicable to each check.

Finally, guidance for applicability to tactical environments is provided.

GUIDELINES FOR SITES WITHOUT A FN PRESENCE:

The following physical controls should be used (individually or collectively) as a guide to evaluate compliance and can be recommended for site use; however, any method or combination of methods clearly being used successfully by the site under review may be acceptable.

POSSIBLE SOLUTIONS:
1. The best physical control solution is to locate all US Only classified terminals (open SIPRNet) in areas where only persons with at least a secret (or higher) security clearance have unescorted access. This type of area is commonly known as a secret Controlled Access Area (CAA). Placement of classified terminals in more highly controlled spaces like in secret or top secret (TS) vaults or secure rooms or SCIFs meets the access control requirements of a secret or TS CAA in addition to providing superior physical security of the location. Such additional physical security protection may be appropriate depending on organization mission and need to continually maintain classified information processing equipment within an open storage environment.
 
2.  Regardless of the type of environment in which classified work stations/monitors are located, ensuring that uncleared persons or those without need-to-know do not have easy access or inadvertent visibility to the classified monitor screens can be accomplished by placing (grouping together) the classified work stations in the back of such rooms/areas or behind partitions. This ensures uncleared visitors have limited opportunity to walk by a classified monitor and inadvertently be exposed to classified data.

3.  If isolation (grouping in controlled space) of the terminals is not practical, a privacy filter should be placed on each classified (SIPRNET) monitor to prevent ease of observation by any unauthorized individual simply passing by. This is a good idea even if other physical controls of classified work stations are used. The use of the privacy filters is an excellent alternative solution where physical separation or repositioning of monitors in rooms is not possible due to space limitations.

4. Classified monitor screens should not be placed facing doorways or windows through which public or unrestricted viewing of the monitor is possible. If space limitations do not allow for such placement then ensuring doors are closed or that windows are covered by screens or blinds during classified processing can be used - but only if this procedure is part of documented security procedures and security training.
  
5. Finally a solution for areas where work stations (cubes) are used is to place doors or the less costly cube screens across the openings for use when classified work is being conducted.

ABSOLUTE REQUIREMENTS:
While the "possible solutions" cover a range of suggest compliance possibilities the following covers an absolute requirement for which there can be no exception:

1.  When uncleared visitors need to enter CAAs, secure rooms, vaults or SCIFs where classified work stations are located there must be a procedure to ensure their presence is announced before entering. This will allow time for screens and classified material to be covered from view.
  
2.  All uncleared visitors must be under continuous escort by a properly cleared employee while within the CAA/secure room/vault/or SCIF. 

GUIDELINES FOR ENVIRONMENTS WITH FN PRESENCE:
  
Environments where FN are present (may even be embedded as US DoD employees) require even more diligence and additional considerations for protection of US Only classified (SIPRNet) terminal screens/workstation screens and monitors. This is because while sharing of certain specific classified information may be permitted, there is always the possibility that US Only or NOFORN information may also be present within the physical environment or accessible on visible/unprotected workstation screens.

Foreign Nationals, even if they are embedded partners in US DoD operations, are not afforded access to any and all US classified information. This erroneous assumption is prevalent in many CC/S/A operation centers where FN liaison and exchange personnel are routinely present. Release of US classified information can only be made to FN partners if specifically compliant with National Disclosure Policy, has been determined releasable to the Foreign National's host country and a Delegation of Disclosure Letter (DDL) has been issued to the specific FN partner to support the release of US classified information or material.

*Where FN are present (regardless of their authorized physical and systems access or security clearance) - US Only work stations and network equipment must be under strict US control at all times.
  
This process involves a combination of physical control measures AND employee awareness. Reviewers must use a flexible approach with an understanding of the synergistic relationship of physical controls and employee awareness to properly evaluate compliance.

REGULATORY STANDARD FOR ENVIRONMENTS WITH FN PRESENCE: This relationship of physical protective measures with employee awareness gained through procedures and training is based on the following excerpt from CJCSI 6510-01F: 
In areas where there is the potential for Foreign National Access to U.S.-Only Workstations and Network Equipment, CC/S/As shall:

1.  Maintain strict U.S. control of U.S.-only workstations and network equipment at all times. This includes network equipment such as printers, copiers, and faxes.

2.  Group U.S.-only workstations together in a U.S.-controlled workstation space when workstations are located in workspaces physically accessible by foreign nationals (such as combined operations centers).

3.  If the grouping of U.S.-only workstations at a site is not operationally possible, the following steps shall be taken:

    a. The U.S. command or agency shall authorize an exception at the site, in writing, stating operational reasons for exception, and maintain the record of exception. NOTE: this exception must be approved by the appropriate CC/S/A level of command, which is normally a 3 or 4 star Flag Officer.

    b. Develop, publish, and maintain specific site written procedures on security measures to safeguard U.S.-only classified workstations.

    c. Ensure that U.S. personnel are briefed and enforce security measures.
    
4.  Announce presence. If a foreign national is permitted access to U.S.-controlled workstation space, the individual must be announced, must wear a badge clearly identifying him or her as a foreign national, and must be escorted at all times. In addition, a warning light must be activated if available and screens must be covered or blanked.

5.  If the foreign national is permitted to view the screen, U.S. personnel must ensure:

    a.  Information is releasable in accordance with CC/S/A guidance and shall be consistent with National Disclosure Policy (NDP)-1; DoDD 5230.11; DoDD 5230.20; DoD Manual 5200.01; and CJCSI 5221.01.

    b.  Check with organization security office to ensure foreign national has security clearances granted by his or her government at a level equal to that of the classified information involved and an official need-to-know.

POSSIBLE SOLUTIONS:
The following physical controls should be used (individually or collectively) as a guide to evaluate compliance and can be recommended for site use; however, any method or combination of methods clearly being used successfully by the site under review may be acceptable:

1.  The "best physical control solution" is to locate all US Only terminals in areas where the FN do not have easy access or visibility to the monitor screens. This can be accomplished by placing them in the back of rooms/areas or behind partitions. Normally if US Only SIPRNet PCs are placed in the back of a room or within the secure space the REL/FN  work stations would then be placed near the front of the area to reduce the frequency of FN officers passing by US Only SIPRNet (or other US Only classified) work stations. When FN employees need to enter areas where US Only work stations are located there should be a procedure to ensure their presence is announced before entering. This will allow time for screens and classified material not releasable to FN to be covered from view.

2.  If isolation of the terminals is not practical, a privacy filter should be placed on each US Only classified (SIPRNET) monitor to prevent ease of observation by any unauthorized individual. This is a good idea even if physical separation of US Only and REL/FN work stations is used. The use of the privacy filters is the best alternative "physical control solution" where physical separation in rooms is not possible due to space limitations and/or the impeding of interaction between US personnel and FN partners.
 
3.  Another acceptable physical security alternative solution for areas where work stations (cubes) are used is to place doors or the less costly cube screens across the openings for when classified work (especially on the US Only cubes) is being performed.
                                                   
4. Finally, in addition to any physical separation, obscuration or other control measures in place (or lack thereof) written local policy/procedures and initial/recurring training are absolutely necessary to ensure that all US personnel are:

    a.  Aware of REL/FN Officers presence in common work areas when working on non-releasable applications/sites on the SIPRNet and

    b.  Aware of exactly what classified or sensitive information is not releasable.

ABSOLUTE REQUIREMENTS:
While the "possible solutions" cover a range of suggest compliance possibilities the following covers an absolute requirement for which there can be no exception:

1.  When uncleared visitors need to enter CAAs, secure rooms, vaults or SCIFs where classified work stations are located there must be a procedure to ensure their presence is announced before entering. This will allow time for screens and classified material to be covered from view.
  
2.  All uncleared visitors must be under continuous escort by a properly cleared employee while within the CAA/secure room/vault/or SCIF.
 
3.  Announce presence of Foreign Nationals (FN). If a foreign national is permitted access to U.S.-controlled workstation space, the individual must be announced, must wear a badge clearly identifying him or her as a foreign national, and must be escorted at all times. In addition, a warning light must be activated if available and screens must be covered or blanked.

4. If the foreign national is permitted to view a US Only screen, U.S. personnel must ensure:

    a.  Information is releasable in accordance with CC/S/A guidance and is consistent with National Disclosure Policy (NDP)-1; DoDD 5230.11; DoDD 5230.20; DoD Manual 5200.01; and CJCSI 5221.01.

    b. A check with the organization security office is conducted to ensure the foreign national has security clearances granted by his or her government at a level equal to that of the classified information involved, that an appropriate DDL is on-hand to validate the security clearance and release of US classified information, and that there is an official need-to-know.

CHECKS FOR *BOTH* US ONLY CLASSIFIED (SIPRNet) ENVIRONMENTS WITHOUT FN PRESENCE AND ENVIRONMENTS WITH FN PRESENCE:

1.  CHECK all classified monitor locations to ensure that no unauthorized viewing is possible or occurring. This includes viewing by uncleared persons and/or those w/o need-to-know. It also includes REL partners or other FN who may have been granted liberal physical access to areas where US ONLY classified is processed. This check is the primary action for reviewers under this requirement. (CAT I)

2.  CHECK/validate that classified monitors cannot be observed from outside the secure space (e.g., from common hallways or through doors or windows).  (CAT I)

3.  CHECK access control procedures and observe actual escort procedures. Ensure there is a process (and that it is actually being used) for announcing unauthorized/uncleared personnel in the area and that uncleared persons and/or those without the need-to-know (to include FN)  are continuously escorted when they are in the immediate vicinity of US classified workstations and components. (CAT I)

CHECKS *ONLY FOR* CLASSIFIED (SIPRNet) ENVIRONMENTS WITH *FN PRESENCE*:

4.  CHECK to ensure there are local written procedures AND adequate documented proof of training (annually minimum) covering rules for interaction between US and FN employees.  All US and FN employees must be equally aware of the rules and procedures.  BOTH must be provided with applicable written guidance and training in this area. (CAT II)

5.  CHECK that U.S.-only workstations are "grouped" together in a U.S.-controlled workstation space when workstations are located in workspaces physically accessible by foreign nationals (such as combined operations centers). (CAT II)

6.  CHECK that If the grouping of U.S.-only workstations at a site is not operationally possible, the following steps have been taken:

    a. The U.S. command or agency has authorized an exception at the site, in writing, stating operational reasons for exception, and maintain the record of exception.  This exception must be approved by the appropriate CC/S/A level of command, which is normally a 3 or 4 star Flag Officer level.  (CAT II)

    b. Develop, publish, and maintain site specific written procedures on security measures to safeguard U.S.-only classified workstations. (in conjunction with written procedures required for CHECK #4) (CAT II)

    c. Ensure that U.S. personnel are briefed, trained (annually minimum) and enforce security measures.  (in conjunction with training required for CHECK #4) (CAT II)

NOTE:  CHECK #6 is an allowable alternative to CHECK #5 and one or the other must be conducted.

7.  CHECK that if a foreign national is permitted to view a US Only screen, U.S. personnel have ensured:

    a.  Information is releasable in accordance with CC/S/A guidance and is consistent with National Disclosure Policy (NDP)-1; DoDD 5230.11; DoDD 5230.20; DoD Manual 5200.01; and CJCSI 5221.01. (CAT I)

    b.  The organization Foreign Disclosure Officer, Foreign Contact Officer, or Security Manager was consulted to  ensure the foreign national has a security clearance granted by his or her government at a level equal to that of the classified information involved, and a Delegation of Disclosure Letter (DDL) has been issued to the specific FN partner to support the release of US classified information or material, and that there is an official need-to-know. (CAT I)

TACTICAL ENVIRONMENT:
 
1. This check is applicable for all classified processing environments including a field/mobile environment. Commanders in such environments may use whatever means available or feasible to control unauthorized physical access to classified monitors.
  
2.  This check is applicable where REL Partners or other FN allies are employed within fixed facilities located in a theater of operations (tactical environment) with physical access to US Classified or Sensitive Systems.

3.  Wherever classified systems/with screens/monitors are used, uncleared persons must always be escorted when permitted in the physical processing environment.)
  desc 'fix', 'REQUIREMENTS FOR BOTH US ONLY CLASSIFIED (SIPRNet) ENVIRONMENTS WITHOUT FN PRESENCE AND ENVIRONMENTS WITH FN PRESENCE:

1.  All classified information system processing locations must have physical and procedural controls to ensure that no unauthorized viewing of monitor screens is possible or occurring. This includes viewing by uncleared persons and/or those w/o need-to-know.  It also includes REL partners or other FN who may have been granted liberal physical access to areas where US ONLY classified is processed.  This is the primary purpose for this STIG Rule requirement.

2.  Classified monitor screens must not be visible or capable of being observed from outside the secure space (e.g., from common hallways or through doors or windows).
  
3.  There must be a visitor/escort control procedure in place (that it is actually being used) for announcing unauthorized/uncleared personnel in the area and that uncleared persons and/or those without the need-to-know (to include FN)  are continuously escorted when they are in the immediate vicinity of US classified workstations and components.
 
REQUIREMENTS ONLY FOR CLASSIFIED (SIPRNet) ENVIRONMENTS WITH FN PRESENCE:

4.  There must be local written procedures AND adequate documented proof of training (annually minimum) covering rules for interaction between US and FN employees.  All US and FN employees must be equally aware of the rules and procedures.  BOTH must be provided with applicable written guidance and training in this area.

5.  U.S.-only workstations must be "grouped" together in a U.S.-controlled workstation space when workstations are located in workspaces physically accessible by foreign nationals (such as combined operations centers).
 
6.  If the grouping of U.S.-only workstations at a site is not operationally possible, the following steps must be taken:

    a. The U.S. command or agency must authorize an exception at the site, in writing, stating operational reasons for exception, and maintain the record of exception.  This exception must be approved by the appropriate CC/S/A level of command, which is normally a 3 or 4 star Flag Officer level.
  
    b. Develop, publish, and maintain site specific written procedures on security measures to safeguard U.S.-only classified workstations. (in conjunction with written procedures under requirement #4)
 
    c. U.S. personnel must be briefed, trained (annually minimum) and enforce security measures. (in conjunction with training under requirement #4)

NOTE:  Requirement #6 is an allowable alternative to Requirement #5 and one or the other must be conducted.

7.  If a foreign national is permitted to view a US Only screen, U.S. personnel must first ensure:

    a.  Information is releasable in accordance with CC/S/A guidance and is consistent with National Disclosure Policy (NDP)-1; DoDD 5230.11; DoDD 5230.20; DoD Manual 5200.01; and CJCSI 5221.01.

    b.  The organization Foreign Disclosure Officer, Foreign Contact Officer, or Security Manager must be consulted to  ensure the foreign national has a security clearance granted by his or her government at a level equal to that of the classified information involved, and a Delegation of Disclosure Letter (DDL) has been issued to the specific FN partner to support the release of US classified information or material, and that there is an official need-to-know.'
  impact 0.7
  ref 'DPMS Target Traditional Security Checklist'
  tag check_id: 'C-49260r770329_chk'
  tag severity: 'high'
  tag gid: 'V-245829'
  tag rid: 'SV-245829r770333_rule'
  tag stig_id: 'IS-08.01.01'
  tag gtitle: 'IS-08.01.01'
  tag fix_id: 'F-49215r770332_fix'
  tag 'documentable'
  tag legacy: ['SV-42290r3_rule', 'V-31991']
end
