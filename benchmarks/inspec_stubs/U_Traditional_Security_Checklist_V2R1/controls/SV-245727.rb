control 'SV-245727' do
  title 'Classified Transmission - Electronic Means using Cryptographic System Authorized by the Director, NSA'
  desc 'Failure to properly encrypt classified data in transit can lead to the loss or compromise of classified or sensitive information.

REFERENCES:

DoD 5200.22-M (NISPOM), Incorporating Change 2, 18 May 2016 Chapter 5, Section 4, paragraphs 5-402.c. and 5-403
 
DoD Manual 5200.01, Volume 3, 24 February 2012, SUBJECT: DoD Information Security Program: Protection of Classified Information:
Encl 4, para 1.a. 
Encl 4, para 3.b. and 4.a.
Encl 4, para 8.
Encl 7, para 13.e.

NIST Special Publication 800-53 (SP 800-53), Rev 4, Controls:  AC-17(2) and SC-8

NSA/CSS Policy Manual 3-16, Sections III, VI, X and XI 

DoD Instruction 8523.01, Communications Security (COMSEC), April 22, 2008, paragraph 6.1.

CJCSI 6510.01F, INFORMATION ASSURANCE (IA) AND SUPPORT TO COMPUTER NETWORK DEFENSE (CND), Enclosure C, paragraph 35.

CNSSI No.7003, September 2015, Protected Distribution Systems (PDS), SECTION IV - POLICY, paragraphs 6, 7 and 8.'
  desc 'check', 'GENERAL REQUIREMENT: Classified information shall be transmitted by electronic means over an approved secure communications system authorized by the Director, NSA, or a Protected Distribution System (PDS) designed and installed to meet the requirements of Committee on National Security Systems Instruction (CNSSI) 7003. This applies to voice, data, message (both organizational and email), and facsimile transmissions. 

CHECK: Where classified (SIPRNet) transmissions are outside of an area approved for unprotected transmission check that the cryptographic system is designed and installed IAW NSA approved guidelines. Generally an area not approved for unprotected SIPRNet transmissions will be any transmission through an area that is not a SCIF, Secret or higher Vault or Secure Room or Secret or higher Controlled Access Area (CAA).

NOTES:

1. This check is applicable in a tactical environment regardless if the unprotected SIPRNet transmission line is located within a fixed facility, or field/mobile environment.

2. This check is NA if the unencrypted signal is installed in a proper Protected Distribution System (PDS).'
  desc 'fix', 'When classified (particularly SIPRNet) voice, data, message (both organizational and e-mail), and facsimile transmissions transit an area not access controlled to at least the Secret level a cryptographic system designed and installed IAW NSA approved guidelines must be used to protect the data in transit.  This check is NA if the transmission line/cable is installed in a proper Protected Distribution System (PDS).'
  impact 0.7
  ref 'DPMS Target Traditional Security Checklist'
  tag check_id: 'C-49158r769841_chk'
  tag severity: 'high'
  tag gid: 'V-245727'
  tag rid: 'SV-245727r769843_rule'
  tag stig_id: 'CS-03.01.01'
  tag gtitle: 'CS-03.01.01'
  tag fix_id: 'F-49113r769842_fix'
  tag 'documentable'
  tag legacy: ['V-30934', 'SV-40976r4_rule']
end
