control 'SV-245786' do
  title 'Information Assurance - Unauthorized Wireless Devices - Portable Electronic Devices (PEDs) Used in Classified Processing Areas without Certified TEMPEST Technical Authority (CTTA) Review and Authorizing Official (AO) Approval.'
  desc 'Allowing wireless devices in the vicinity of classified processing or discussion could directly result in the loss or compromise of classified or sensitive information either intentionally or accidentally.

REFERENCES:

CJCSI 6510.01F, INFORMATION ASSURANCE (IA) AND SUPPORT TO COMPUTER NETWORK DEFENSE (CND), Encl C, paragraphs 21.i(3). and  22.

CNSS Directive No. 510, 20 November 2017, Directive on the Use of Mobile Devices Within Secure Spaces

NIST Special Publication 800-53 (SP 800-53), Rev 4, Controls: 
AC-18, AC-18(1), AC-18(2), AC-18(3), AC-18(4) and AC-19

CNSSP No.29, May 2013, National Secret Enclave Connection Policy

CNSSP No. 17, January 2014, Policy on Wireless Systems

DISN Connection Process Guide:
http://disa.mil/network-services/enterprise-connections/connection-process-guide

Wireless STIG

Mobility Policy Manual STIG

DoDD 8100.02, Use of Commercial Wireless Devices, Services, and Technologies in the Department of Defense (DoD) Global Information Grid (GIG), paragraphs 4.2. and 4.3

CNSSI 1400, National Instruction on the use of Mobile Devices within Secure Spaces

Joint USD(I) and DoD CIO Memorandum, dated 25, Sep 2015, SUBJECT: Security and Operational Guidance for Classified Portable Electronic Devices'
  desc 'check', '1. Check to ensure that unauthorized wireless devices (PEDs such as cellphones, BlackBerry devices, laptops, etc.) are not being used in areas where classified systems or machines (SIPRNet) are in use.
 
2. If PED usage in classified processing areas is permitted by the site, check to ensure there is specific written AO (formerly DAA) approval and that a CTTA has assessed the environment and that any resulting recommended TEMPEST countermeasures have been implemented.
  
TACTICAL ENVIRONMENT: The check is applicable for ALL classified processing environments.'
  desc 'fix', '1. Unauthorized wireless devices (PEDs such as cellphones, BlackBerry devices, laptops, etc.) must not be permitted for use in areas where classified systems or machines (SIPRNet) are in use.
 
2. If PED usage in classified processing areas is permitted, there must be specific written AO (formerly DAA) approval and a CTTA assessment of the environment and any resulting recommended TEMPEST countermeasures must be implemented.'
  impact 0.5
  ref 'DPMS Target Traditional Security Checklist'
  tag check_id: 'C-49217r770299_chk'
  tag severity: 'medium'
  tag gid: 'V-245786'
  tag rid: 'SV-245786r770301_rule'
  tag stig_id: 'IA-11.02.01'
  tag gtitle: 'IA-11.02.01'
  tag fix_id: 'F-49172r770300_fix'
  tag 'documentable'
  tag legacy: ['V-31128', 'SV-41275r3_rule']
end
