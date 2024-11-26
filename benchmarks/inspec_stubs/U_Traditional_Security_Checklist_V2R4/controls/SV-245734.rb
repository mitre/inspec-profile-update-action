control 'SV-245734' do
  title 'Protected Distribution System (PDS) Construction - Tactical Environment Application'
  desc 'A PDS that is not constructed and configured as required could result in the undetected interception of classified information. Within mobile tactical situations a hardened carrier is not possible and therefore the unencrypted SIPRNet cable must be maintained within the confines of the tactical encampment with the cable under continuous observation and control to prevent exploitation by enemy forces. In theaters of operation where fixed facilities are well established, standard PDS applications must be employed unless a risk assessment is conducted to determine the vulnerabilities and risks associated with using unencrypted cable that is not in a hardened carrier.

REFERENCES:  
                               
CJCSI 6510.01F, INFORMATION ASSURANCE (IA) AND SUPPORT TO COMPUTER NETWORK DEFENSE (CND), Enclosure C, paragraph 35.c.

DoD 5220.22-M (NISPOM), Incorporating Change 2, 18 May 2016 Chapter 5, Section 4, paragraphs 5-402.c. and 5-403
   
DoD Manual 5200.01, Volume 3, 24 February 2012, SUBJECT: DoD Information Security Program: Protection of Classified Information, Encl 4, para 3.b. and 4.a.

NIST Special Publication 800-53 (SP 800-53), Rev 4, Controls:  PE-4, SC-7, and SC-8

Former guidance was in the legacy/superseded NSTISSI 7003, Protected Distribution Systems, Annex B, paragraph 1.a.(7)

NOTE: There is no longer specific guidance in the updated CNSSI 7003 but the guidance for Continuously Viewed Carriers is the most applicable for Tactical Environments with PDS:
CNSSI No.7003, September 2015, Protected Distribution Systems (PDS), Section X, paragraph 30.e.'
  desc 'check', %q(PDS in a tactical environment.  Check to ensure:
  
1. The PDS is located within the limits of the installation and command post, or in an area directly under the commander's physical control.
  
2. Continuously viewed Carriers must be used in tactical environments with mobile systems employing inter-shelter cabling. 
 
3. Continuously viewed Carriers may also be used in tactical environments with "fixed facilities" ONLY if it is determined through a documented Risk Assessment that the cost or feasibility to install a Category 2 PDS (Hardened or Alarmed Carrier) is not warranted. If applicable based on the risk assessment STIG ID VULS CS-04.01.01 through CS-04.01.06 may be used for fixed facilities in a theater of operations.
  
4. ALL PDS in a tactical environment must be included in a well-documented Risk Assessment, for which residual risk has been acknowledged and accepted by the PDS Approval Authority.)
  desc 'fix', %q(PDS in a tactical environment:
   
1. The PDS must be located within the limits of the installation and command post, or in an area directly under the commander's physical control.
  
2. Continuously viewed Carriers must be used in tactical environments with mobile systems employing inter-shelter cabling.
  
3. Continuously viewed Carriers may also be used in tactical environments with "fixed facilities" ONLY if it is determined through a documented Risk Assessment that the cost or feasibility to install a Category 2 (Hardened or Alarmed Carrier) is not warranted. If applicable based on the risk assessment STIG ID VULS CS-04.01.01 through CS-04.01.06 may be used for fixed facilities in a theater of operations.
 
4. ALL PDS in a tactical environment must be included in a well-documented Risk Assessment, for which residual risk has been acknowledged and accepted by the PDS Approval Authority.)
  impact 0.7
  ref 'DPMS Target Traditional Security Checklist'
  tag check_id: 'C-49165r769862_chk'
  tag severity: 'high'
  tag gid: 'V-245734'
  tag rid: 'SV-245734r822801_rule'
  tag stig_id: 'CS-04.01.07'
  tag gtitle: 'CS-04.01.07'
  tag fix_id: 'F-49120r769863_fix'
  tag 'documentable'
  tag legacy: ['V-30973', 'SV-41015r3_rule']
end
