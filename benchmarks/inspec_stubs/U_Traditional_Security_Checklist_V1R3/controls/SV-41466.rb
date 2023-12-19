control 'SV-41466' do
  title 'Foreign National (FN) Physical Access Control -  (Identification Badges)'
  desc 'Failure to limit access to information visible on system monitor screens in mixed US/FN environments can result in FN personnel having unauthorized access to classified information, which can result in the loss or compromise of classified information, including NOFORN information.  Physically co-locating REL Partners or other FN - who have limited access to the SIPRNet or other US Classified systems - near US personnel in a collateral classified (Secret) open storage area or in a Secret Controlled Access Area (CAA) that processes classified material is permissible for operational efficiency and coordination.  Appropriate but simple physical and procedural security measures must be put in place to ensure the FN partners do not have unauthorized access to information not approved for release to them. Ensuring that US employees can clearly identify FN workers is an important control measure and can be accomplished by requiring the FN employees or partners to wear picture identification badges that clearly identify their affiliated / represented Country.  Wearing of Country specific military uniforms also can be used.

REFERENCES:

National Disclosure Policy - 1 (NDP-l) 

National Security Directive 42, "National Policy for the Security of National Security Telecommunications and Information Systems" 

DODD 5230.11, Disclosure of Classified Military Information to Foreign Governments and International Organizations SPECIAL NOTE: Enclosure 3 to DODD 5230.11 establishes specific criteria for the disclosure of classified information.

Use guidance on sharing information with REL Partners on SIPRNET at http://www.ssc.smil.mil/ - follow Policy/Guidance&Documentation link and then SIPRNet Information Sharing...

DODD 5230.20; Visits, Assignments, and Exchanges of Foreign Nationals

CJCSI 6510.01F, INFORMATION ASSURANCE (IA) AND SUPPORT TO COMPUTER NETWORK DEFENSE (CND), Encl C, para 27.f.(4).

NIST Special Publication 800-53 (SP 800-53), Rev 4, Controls: 
PE-2, PE-3, PE-5, PE-6, PE-8, PE-18

DoDI 8500.01, SUBJECT: Cybersecurity, March 14, 2014, Enclosure 3, paragraph 11.                                    

DoD Manual 5200.02, Procedures for the DoD Personnel Security Program (PSP), 3 April 2017

DoD Manual 5200.01, Volume 1, SUBJECT: DoD Information Security Program: Overview, Classification, and Declassification, Encl 2, para 9.j.(1) and Encl 3,  para 5.b., 7.b.(5), 12.e.

DoD Manual 5200.01, Volume 3, SUBJECT: DoD Information Security Program: Protection of Classified Information, Encl 7.

DoD 5200.22-M (NISPOM), Incorporating Change 2, 18 May 2016, CHAPTER 10
International Security Requirements, Section 5. International Visits and Control of Foreign Nationals'
  desc 'check', 'Check to ensure foreign local nationals (LN) hired by DOD organizations overseas IAW the applicable SOFA are issued and wear identification/access badges that clearly distinguish them as foreign national employees. REL Partners and FN Liaison and Exchange personnel in OCONUS and CONUS locations must also be provided and wear identification/access badges that clearly distinguish them as foreign national partners.  If practical they should also be required to wear the military uniform of their host country - although FN out of uniform should not be an automatic finding. The intent is to enable US personnel to clearly distinguish between FN and US personnel. 

Following is an applicable excerpt from CJCSI 6510.01F pertaining to controlled US Only workstation spaces:
Announce presence. If a foreign national is permitted access to controlled US work station space, the individual must be announced, must wear a badge clearly identifying him or her as a FN, and must be escorted at all times. In addition a warning light must be activated if available and screens must be covered or blanked.
  
TACTICAL ENVIRONMENT: This check is applicable where LN/FN are employed in a tactical environment with access to US Systems.'
  desc 'fix', '1. "Foreign" local nationals (LN) hired by DOD organizations overseas IAW the applicable SOFA must be issued and wear identification/access badges that clearly distinguish them as foreign national employees. 

2. REL Partners and FN Liaison and Exchange personnel in both OCONUS and CONUS locations must also be provided and wear identification/access badges that clearly distinguish them as foreign national partners. 

If practical they should also be required to wear the military uniform of their host country - although FN out of uniform should not be an automatic finding. 

The intent is to enable US personnel to clearly distinguish between FN and US personnel. 

Following is an applicable excerpt from CJCSI 6510.01F pertaining to controlled US Only workstation spaces: Announce presence. If a foreign national is permitted access to controlled US work station space, the individual must be announced, must wear a badge clearly identifying him or her as a FN, and must be escorted at all times. In addition a warning light must be activated if available and screens must be covered or blanked.'
  impact 0.3
  ref 'DPMS Target Traditional Security'
  tag check_id: 'C-39967r6_chk'
  tag severity: 'low'
  tag gid: 'V-31243'
  tag rid: 'SV-41466r3_rule'
  tag stig_id: 'FN-04.03.01'
  tag gtitle: 'Foreign National (FN) Physical Access Control -  (ID Badges)'
  tag fix_id: 'F-35137r4_fix'
  tag 'documentable'
end
