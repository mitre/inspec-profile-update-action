control 'SV-41269' do
  title 'Information Assurance - Classified Portable Electronic Devices (PEDs) Connected to the SIPRNet must be Authorized, Compliant with NSA Guidelines, and be Configured for Data at Rest (DAR) Protection'
  desc 'Finding unauthorized and/or improperly configured wireless devices (PEDs) connected to and/or operating on the SIPRNet is a security incident and could directly result in the loss or compromise of classified or sensitive information either intentionally or accidentally. 

An assessment of risk in accordance with the Risk Management Framework (RMF) along with Certification and Accreditation and an Authorization to Operate (ATO) must be  accomplished and documented prior to connecting NSA approved classified PED solutions on a classified network such as SIPRNet or using PEDs within a classified enclave.

A key requirement is that classified PEDs used to store classified data must comply with either the NSA Data At Rest (DAR) Capability Package and associated Risk Assessment or achieve NSA approval as a Tailored Solution for protection of data at rest.

Handling procedures should include guidance provided in NSA risk assessments and may involve two layers of National Information Assurance Partnership (NIAP)-approved DAR protection, shipping/storage in accordance with Reference (a), and programmed data wiping or certificate revocation.

REFERENCES:

CJCSI 6510.01F, INFORMATION ASSURANCE (IA) AND SUPPORT TO COMPUTER NETWORK DEFENSE (CND), Encl C, paragraphs 21.i. and  22.

NIST Special Publication 800-53 (SP 800-53), Rev 4, Controls: 
AC-18, AC-18(1), AC-18(2), AC-18(3), AC-18(4) and AC-19

CNSSP No.29, May 2013, National Secret Enclave Connection Policy

CNSSP No. 17, January 2014, Policy on Wireless Systems

DISN Connection Process Guide:
http://disa.mil/network-services/enterprise-connections/connection-process-guide

Wireless STIG

Mobility Policy Manual STIG

DoDD 8100.02, Use of Commercial Wireless Devices, Services, and Technologies in the Department of Defense (DoD) Global Information Grid (GIG), paragraph 4.1.3.

CNSSI 1400, National Instruction on the use of Mobile Devices within Secure Spaces

Joint USD(I) and DoD CIO Memorandum, dated 25, Sep 2015, SUBJECT: Security and Operational Guidance for Classified Portable Electronic Devices

NSA "Mobile Access Capability Package vl .0," April 2, 2015 or later

NSA "Mobile Access Risk Assessment vi .0," March 27, 2015 or later

DoD Instruction 8510.01, "Risk Management Framework (RMF) for DoD Information
Technology (IT)," March 12, 2014

NSA "Commercial Solutions for Classified (CSfC) Incident Reporting Guidelines vl .0,"
June 18, 2014 or later

NSA "Data at Rest Capability Package v 2.0," April 2, 2015 or later

NSA "Data at Rest Risk Assessment v2.0," April 7, 2015 or later

DoD Instruction 8420.01, Commercial Wireless Local Area Network (WLAN) Devices, Systems, and Technologies, 3 November 2017, Paragraphs 1.2.h., and 3.8.d.'
  desc 'check', '1. Visually check during the walk-around to ensure that unauthorized wireless devices (e.g., PEDs) are not connected to the Network (SIPRNet). 

NOTE: Portable Electronic Devices (PEDs) include but are not limited to tablets, laptops, smartphones, and cellular telephones.

2. Consult with Network Reviewers and Wireless Scanners to ensure they have not detected unauthorized wireless devices.  

3. If Portable Electronic Devices (PEDs) are found connected to the SIPRNet, verify with both site security personnel, Network Reviewers and others as necessary (e.g., site ISSM) that all devices are NSA approved/configured and meet requirements for Data at Rest (DAR) encryption.

4. Verify that SIPRNet connected PEDs comply with all requirements in the "Joint USD(I) and DoD CIO Memorandum, dated 25 September 2015, SUBJECT: Security and Operational Guidance for Classified Portable Electronic Devices".

TACTICAL ENVIRONMENT: The check is applicable for ALL classified processing environments.'
  desc 'fix', 'Unauthorized wireless devices, such as phones, PEDs, Laptops, etc., must not be connected to the SIPRNet or other classified system/network being reviewed.

Ensure that unauthorized wireless devices (e.g., PEDs) are not connected to the Network (SIPRNet). 

NOTE: Portable Electronic Devices (PEDs) include but are not limited to tablets, laptops, smartphones, and cellular telephones.

If Portable Electronic Devices (PEDs) are connected to the SIPRNet, all devices must be NSA approved/configured and meet requirements for Data at Rest (DAR) encryption.

All SIPRNet connected PEDs must comply with requirements in the "Joint USD(I) and DoD CIO Memorandum, dated 25 September 2015, SUBJECT: Security and Operational Guidance for Classified Portable Electronic Devices".'
  impact 0.7
  ref 'DPMS Target Traditional Security'
  tag check_id: 'C-39819r9_chk'
  tag severity: 'high'
  tag gid: 'V-31127'
  tag rid: 'SV-41269r3_rule'
  tag stig_id: 'IA-11.01.01'
  tag gtitle: 'Information Assurance - Wireless Devices Connected to SIPRNet'
  tag fix_id: 'F-35016r8_fix'
  tag 'documentable'
end
