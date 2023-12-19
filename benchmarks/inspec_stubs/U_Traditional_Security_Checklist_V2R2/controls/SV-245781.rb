control 'SV-245781' do
  title 'Information Assurance - KVM or A/B Switch not listed on the NIAP U.S. Government Approved Protection Products Compliance List (PCL) for Peripheral Sharing Switches'
  desc 'Failure to use tested and approved switch boxes can result in the loss or compromise of classified information.

REFERENCES:

NIST Special Publication 800-53 (SP 800-53), Rev 4, Controls: 
SC-3 and SC-4

DISN Connection Process Guide:
http://disa.mil/network-services/enterprise-connections/connection-process-guide

NIAP Products Compliance List (PCL):
https://www.niap-ccevs.org/index.cfm'
  desc 'check', "1. Check all KVM or A/B switches that switch from NIPR to SIPR - or other low side to high side systems being reviewed.

2. Ensure switches are on the most current approved NIAP Approved Products List (APL) are used for switching between high side and low side devices.

3. Check to ensure that any unapproved switch boxes in use have specific approval for use in the SIPRNet Approval to Connect (ATC) or (IATC) from the Classified Connection Approval Office (CCAO).

NOTE: A KVM used for switching between high (SIPRNet) and low (NIPRNet) shared devices must meet one or both of the following basic criteria:
a. Be on the NIAP Approved Products List (APL) (AKA: Validated Products List [VPL]) AND meet any configuration requirements for the sites' IA environment as a minimum requirement to be used on the DODIN.  
b. Based on the NIAP/APL approved products list, the devices listed may be used for switching between peripheral devices across high/low (SIPR/NIPR) domains.

TACTICAL ENVIRONMENT: The check is applicable where KVM devices are in use."
  desc 'fix', "1. All KVM or A/B switches that switch from NIPR to SIPR - or other low side to high side systems being reviewed must be on the most current approved NIAP Approved Products List (APL) for use for switching between high side and low side devices. 

2. Any unapproved switch boxes in use (switching from NIPR to SIPR) must have specific approval for use and be addressed in the SIPRNet Approval to Connect (ATC) or IATC from the Classified Connection Approval Office (CCAO). 

NOTE: A KVM used for switching between high (SIPRNet) and low (NIPRNet) shared devices must meet one or both of the following basic criteria:
a. Be on the NIAP Approved Products List (APL) (AKA: Validated Products List [VPL]) AND meet any configuration requirements for the sites' IA environment as the minimum requirement to be used on the DODIN. 
b. Based on the NIAP/APL approved products list, the devices listed may be used for switching between peripheral devices across high/low (SIPR/NIPR) domains."
  impact 0.5
  ref 'DPMS Target Traditional Security Checklist'
  tag check_id: 'C-49212r864547_chk'
  tag severity: 'medium'
  tag gid: 'V-245781'
  tag rid: 'SV-245781r865846_rule'
  tag stig_id: 'IA-10.02.01'
  tag gtitle: 'IA-10.02.01'
  tag fix_id: 'F-49167r864548_fix'
  tag 'documentable'
  tag legacy: ['V-31115', 'SV-41244r3_rule']
end
