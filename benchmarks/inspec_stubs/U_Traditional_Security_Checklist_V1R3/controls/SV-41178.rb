control 'SV-41178' do
  title 'Information Assurance - SIPRNET Connection Approval Process (CAP)'
  desc 'Failure to provide current connection documentation to the DISN Connection Approval Office (CAO) and allowing a system to connect and operate without a current CAO approval can result in a vulnerability to all SIPRNet connected systems on the DISN.

REFERENCES:

CJCSI 6510.01F, INFORMATION ASSURANCE (IA) AND SUPPORT TO COMPUTER NETWORK DEFENSE (CND), Encl C, para 18.a.

NIST Special Publication 800-53 (SP 800-53), Rev 4, Controls: 
AC-3, AC-3(2), AC-20

DoDI 8500.01, SUBJECT: Cybersecurity, March 14, 2014 

DoD Instruction 8510.01, SUBJECT: Risk Management Framework (RMF) for DoD Information Technology (IT)

CJCSI 6211.02D, DEFENSE INFORMATION SYSTEMS NETWORK (DISN) RESPONSIBILITIES,
Encl B, para 2.f. and Encl D, para 5.j.(1)

CNSSP No.29, May 2013, National Secret Enclave Connection Policy

DISN Connection Process Guide:
http://disa.mil/network-services/enterprise-connections/connection-process-guide'
  desc 'check', '1. Check to ensure the site provided the DISN Connection Approval Office (CAO), current certification documentation IAW CAO guidance. 

2. In addition check to ensure the site also has notified the CAO of any changes/modification to the approved architecture.  

3. Check to ensure the approval to connect (ATC) or Interim Approval to Connect (IATC) is current.

TACTICAL ENVIRONMENT: The check is applicable. The ATC and associated documentation should be found in a fixed HQ location where the ISSM/ISSO are located. When possible, documentation should be requested/sought before departing on trips to tactical locations. Copies sent to the reviewers email (NIPR or SIPR depending on classification of document) can be used to validate compliance.'
  desc 'fix', '1. The DISN Connection Approval Office (CAO) must be provided with current certification documentation IAW CAO guidance. 

2. The CAO must be notified in writing of any changes/modification to the approved architecture. 

3. The approval to connect (ATC) or Interim Approval to Connect (IATC) must be current.'
  impact 0.5
  ref 'DPMS Target Traditional Security'
  tag check_id: 'C-39724r8_chk'
  tag severity: 'medium'
  tag gid: 'V-31091'
  tag rid: 'SV-41178r3_rule'
  tag stig_id: 'IA-09.02.01'
  tag gtitle: 'Information Assurance - SIPRNET CAP'
  tag fix_id: 'F-34922r4_fix'
  tag 'documentable'
end
