control 'SV-245848' do
  title 'Controlled Unclassified Information - Posting Only on Web-Sites with Appropriate Encryption; not on Publicly Accessible Web-Sites.'
  desc 'Failure to handle CUI in an approved manner can result in the loss or compromise of sensitive information.

REFERENCES:

Executive Order 13556, Controlled Unclassified Information (CUI)

The Information Security Oversight Office (ISOO): https://www.archives.gov/cui

Deputy Secretary of Defense Memorandum, "WEB Site Administration" 7 Dec 98, with attached "WEB Site Administration Policies and Procedures", 25 Nov 98.

DoD 5400.7-R, DoD Freedom of Information Act Program, Sep 98.

DoD 5400-11-R, Department of Defense Privacy Program, 14 May 07.

DoDD 5230.09, 22 Aug 08, Clearance of DoD Information for Public Release

DoDI 5230.29, 8 Jan 09, Security and Policy Review of DoD Information for Public Release.

PL 104-191, 21 Aug 96, Health Insurance Portability and Accountability Act of 1996

NIST FIPS 140-2, Security Requirements for Cryptographic Modules

DODI 8520.2, "Public Key Infrastructure (PKI) and Public Key Enabling (PKE)"

CJCSI 6510.01F, INFORMATION ASSURANCE (IA) AND SUPPORT TO COMPUTER NETWORK DEFENSE (CND); Enclosure A, paragraph 7.a. and Enclosure C, paragraph 26.i. 

NIST Special Publication 800-53 (SP 800-53), Rev 4, Controls: AC-14, AC-17, IA-8 and SC-7.

DoD Manual 5200.01, Volume 3, 24 February 2012, SUBJECT: DoD Information Security Program: Protection of Classified Information; Enclosure 7, paragraph 13.f..

DoD Manual 5200.01, Volume 4, SUBJECT: DoD Information Security Program: Controlled Unclassified Information (CUI); Enclosure 3., paragraphs 1.f, 2.e.(3) and 5.e.(4).

DoD 5200.22-M (NISPOM), Incorporating Change 2, 18 May 2016, Chapter 1, Section 3, paragraph 1-300.b.&c., Chapter 5, Section 5, paragraph 5-511 and Chapter 7, Section 1, paragraph 7-102.'
  desc 'check', 'Check to ensure the following standards/guidance are adhered to: 

1.  FOUO, PII and other CUI may NOT be posted to publicly-accessible Internet sites and may NOT be posted to sites whose access is controlled only by domain (e.g., limited to .mil and/or .gov) as such restricted access can easily be circumvented. 

2.  At a minimum, posting CUI to a website requires certificate-based (e.g., common access card) or password and ID access as well as encrypted transmission using https: or similar technology. CUI other than FOUO may have additional posting restrictions. 

3.  See Deputy Secretary of Defense Memorandum Web Site Administration, December 7, 1998, with attached Web Site Administration Policies and Procedures, November 25, 1998 for detailed guidance. 

TACTICAL ENVIRONMENT: The check is applicable for fixed (established) tactical processing environments where procedural documents (SOPs) should be in place.  Not applicable to a field/mobile environment.'
  desc 'fix', 'Ensure the following standards/guidance are adhered to: 

1.  FOUO, PII and other CUI may NOT be posted to publicly-accessible Internet sites and may NOT be posted to sites whose access is controlled only by domain (e.g., limited to .mil and/or .gov) as such restricted access can easily be circumvented. 

2.  At a minimum, posting CUI to a website requires certificate-based (e.g., common access card) or password and ID access as well as encrypted transmission using https: or similar technology. CUI other than FOUO may have additional posting restrictions. 

3.  See Deputy Secretary of Defense Memorandum Web Site Administration, December 7, 1998, with attached Web Site Administration Policies and Procedures, November 25, 1998 for detailed guidance.'
  impact 0.5
  ref 'DPMS Target Traditional Security Checklist'
  tag check_id: 'C-49279r770204_chk'
  tag severity: 'medium'
  tag gid: 'V-245848'
  tag rid: 'SV-245848r770206_rule'
  tag stig_id: 'IS-16.02.06'
  tag gtitle: 'IS-16.02.06'
  tag fix_id: 'F-49234r770205_fix'
  tag 'documentable'
  tag legacy: ['V-32265', 'SV-42582r3_rule']
end
