control 'SV-245781' do
  title 'Information Assurance - KVM or A/B Switch not listed on the NIAP U.S. Government Approved Protection Products Compliance List (PCL) for Peripheral Sharing Switches'
  desc 'Failure to use tested and approved switch boxes can result in the loss or compromise of classified information.

REFERENCES:

Keyboard, Video, Mouse Switch Security STIG 

DISN Peripheral Sharing Device Guidance: Defense IA/Security Accreditation Working Group (DSAWG) August 2009 - NOTE the DSAWG Meeting Minutes that published KVM guidance were originally from 2006 and last updated in May 2014 - but retains an August 2009 date on the cover of the Power Point slides.

NIST Special Publication 800-53 (SP 800-53), Rev 4, Controls: 
SC-3 and SC-4

DISN Connection Process Guide:
http://disa.mil/network-services/enterprise-connections/connection-process-guide

NIAP Products Compliance List (PCL):
https://www.niap-ccevs.org/index.cfm'
  desc 'check', '1. Check all KVM or A/B switches that switch from NIPR to SIPR - or other low side to high side systems being reviewed.

2. Ensure switches are on the most current approved NIAP Product Compliance List (PCL) or are on the latest DSAWG approved list or otherwise comply with DSAWG guidance for use for switching between high side and low side devices. 

3. Check to ensure that any unapproved switch boxes in use  have specific approval for use in the SIPRNet Approval to Connect (ATC) or (IATC) from the Classified Connection Approval Office (CCAO).

NOTE:

A KVM used for switching between high (SIPRNet) and low (NIPRNet) shared devices must meet one or both of the following basic criteria:

a. Be on the NIAP Products Compliance List (PCL) (AKA: Validated Products List (VPL)) AND meet any configuration requirements as directed in the "Keyboard, Video, Mouse Switch Security STIG" formerly called the "Sharing Peripherals Across the Network STIG" as the minimum requirement to be used on the DoDIN. This is based on slide #2 of the DSAWG guidance.

b. Based on slide #3 of the DSAWG guidance an additional requirement of being on one of the specified Intelligence Community (IC) approved products lists or on the DSAWG Approved KVM list may be used for switching between peripheral devices across high/low (SIPR/NIPR) domains.

TACTICAL ENVIRONMENT: The check is applicable where KVM devices are in use.'
  desc 'fix', '1. All KVM or A/B switches that switch from NIPR to SIPR - or other low side to high side systems being reviewed must be on the most current approved NIAP Product Compliance List (PCL) or on the latest DSAWG approved list or otherwise comply with DSAWG guidance for use for switching between high side and low side devices. 

2. Any unapproved switch boxes in use (switching from NIPR to SIPR) must have specific approval for use and be addressed in the SIPRNet Approval to Connect (ATC) or IATC from the Classified Connection Approval Office (CCAO). 

NOTE:

A KVM used for switching between high (SIPRNet) and low (NIPRNet) shared devices must meet one or both of the following basic criteria:

a. Be on the NIAP Products Compliance List (PCL) (AKA: Validated Products List (VPL)) AND meet any configuration requirements as directed in the "Keyboard, Video, Mouse Switch Security STIG" formerly called the "Sharing Peripherals Across the Network STIG" as the minimum requirement to be used on the DoDIN. This is based on slide #2 of the DSAWG guidance.

b. Based on slide #3 of the DSAWG guidance an additional requirement of being on one of the specified Intelligence Community (IC) approved products lists or on the DSAWG Approved KVM list may be used for switching between peripheral devices across high/low (SIPR/NIPR) domains.'
  impact 0.5
  ref 'DPMS Target Traditional Security Checklist'
  tag check_id: 'C-49212r770003_chk'
  tag severity: 'medium'
  tag gid: 'V-245781'
  tag rid: 'SV-245781r770005_rule'
  tag stig_id: 'IA-10.02.01'
  tag gtitle: 'IA-10.02.01'
  tag fix_id: 'F-49167r770004_fix'
  tag 'documentable'
  tag legacy: ['V-31115', 'SV-41244r3_rule']
end
