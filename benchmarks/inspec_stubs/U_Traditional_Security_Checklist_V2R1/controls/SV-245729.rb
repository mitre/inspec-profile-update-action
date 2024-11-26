control 'SV-245729' do
  title 'Protected Distribution System (PDS) Construction - Hardened Carrier'
  desc 'A PDS that is not constructed and configured as required could result in the undetected interception of classified information.

REFERENCES:

CJCSI 6510.01F, INFORMATION ASSURANCE (IA) AND SUPPORT TO COMPUTER NETWORK DEFENSE (CND), Enclosure C, paragraph 35.c.

DoD 5200.22-M (NISPOM), Incorporating Change 2, 18 May 2016 Chapter 5, Section 4, paragraphs 5-402.c. and 5-403
  
DoD Manual 5200.01, Volume 3, 24 February 2012, SUBJECT: DoD Information Security Program: Protection of Classified Information, Encl 4, para 3.b. and 4.a.

NIST Special Publication 800-53 (SP 800-53), Rev 4, Controls:  PE-4, SC-7, and SC-8

CNSSI No. 7003, September 2015, Protected Distribution Systems (PDS), Section IV, Paragraph 7 and Section X, paragraph 30.a.'
  desc 'check', '1. A Hardened Carrier IAW CNSSI 7003 must be constructed of ferrous, electrical metallic tubing (EMT); ferrous pipe conduit; or ferrous rigid sheet metal ducting. Flexible conduit and armored cables must not be used as a hardened carrier. The carrier must not open to expose data cables (e.g., removable covers), except at approved pull boxes and termination boxes. The carrier must utilize elbows, couplings, nipples, and connectors of the same materials.  All joints and connections must be sealed.

NOTE: A vendor product (AKA: Modular PDS) may be used if constructed of solid metal components and sealed - as described above.

2. The PDS is not within an Uncontrolled Access Area (UAA).'
  desc 'fix', '1. Data cables must be installed in a carrier configured as a "Hardened Carrier" IAW CNSSI 7003. The carrier must be constructed of ferrous, electrical metallic tubing (EMT); ferrous pipe conduit; or ferrous rigid sheet metal ducting. Flexible conduit and armored cables must not be used as a hardened carrier. The carrier must not open to expose data cables (e.g., removable covers), except at approved pull boxes and termination boxes. The carrier must utilize elbows, couplings, nipples, and connectors of the same materials. All joints and connections must be sealed.

NOTE: A vendor product (AKA: Modular PDS) may be used if constructed of solid metal components and sealed - as described above.

2. The PDS must not be located within an Uncontrolled Access Area (UAA).'
  impact 0.7
  ref 'DPMS Target Traditional Security Checklist'
  tag check_id: 'C-49160r769847_chk'
  tag severity: 'high'
  tag gid: 'V-245729'
  tag rid: 'SV-245729r769849_rule'
  tag stig_id: 'CS-04.01.02'
  tag gtitle: 'CS-04.01.02'
  tag fix_id: 'F-49115r769848_fix'
  tag 'documentable'
  tag legacy: ['V-30942', 'SV-40984r4_rule']
end
