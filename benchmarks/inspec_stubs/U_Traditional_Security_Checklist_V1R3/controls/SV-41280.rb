control 'SV-41280' do
  title 'Information Assurance - Unauthorized Wireless Devices - No Formal Policy and/or Warning Signs'
  desc 'Not having a wireless policy and/or warning signs at entrances could result in the unauthorized introduction of wireless devices into classified processing areas.

REFERENCES:

CJCSI 6510.01F, INFORMATION ASSURANCE (IA) AND SUPPORT TO COMPUTER NETWORK DEFENSE (CND), Encl C, paragraphs 21.i(3). and  22.

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
  desc 'check', '1. Check to ensure there is a local wireless policy or SOP.  

2. During the walk-around, ensure there is appropriate signage at entrances notifying employees and visitors that wireless devices are not authorized in a classified facility.

3. Check that wireless policy is included in initial briefings for new employees and reinforced periodically such as during annual security refresher training.   

TACTICAL ENVIRONMENT: The check is applicable to tactical locations where fixed facilities are used for classified processing.  Not applicable to mobile/field environments.'
  desc 'fix', '1. A local wireless policy or SOP must be written and available for employee reference. 

2. There must be appropriate signage at entrances notifying employees and visitors that wireless devices are not authorized in a classified facility. 

3. Wireless policy must be included in initial briefings for new employees and reinforced periodically such as during annual security refresher training.'
  impact 0.3
  ref 'DPMS Target Traditional Security'
  tag check_id: 'C-39827r5_chk'
  tag severity: 'low'
  tag gid: 'V-31129'
  tag rid: 'SV-41280r3_rule'
  tag stig_id: 'IA-11.03.01'
  tag gtitle: 'Information Assurance - Unauthorized Wireless Devices - No Policy or Warning Signs'
  tag fix_id: 'F-35025r4_fix'
  tag 'documentable'
end
