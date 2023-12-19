control 'SV-245784' do
  title 'Information Assurance - Authorizing Official (AO) and DoDIN Connection Approval Office (CAO) Approval Documentation for use of KVM  and A/B switches for Sharing of Classified and Unclassified Peripheral Devices'
  desc 'Failure to request approval for connection of  existing or additional KVM or A/B devices (switch boxes) for use in switching between classified (e.g., SIPRNet) devices and unclassified devices (e.g., NIPRNet) from both the Authorizing Official (AO) and the DoDIN Connection Approval Office could result in unapproved devices being used or approved devices being used or configured in an unapproved manner; thereby increasing the risk for the DoDIN.

REFERENCES:

Keyboard, Video, Mouse Switch Security STIG 

DISN Peripheral Sharing Device Guidance: Defense IA/Security Accreditation Working Group (DSAWG) August 2009 - NOTE the DSAWG Meeting Minutes that published KVM guidance were originally from 2006 and last updated in May 2014 - but retains an August 2009 date on the cover of the Power Point slides.

NIST Special Publication 800-53 (SP 800-53), Rev 4, Controls: 
SC-3 and SC-4

DISN Connection Process Guide:
http://disa.mil/network-services/enterprise-connections/connection-process-guide

NIAP Products Compliance List (PCL):
https://www.niap-ccevs.org/index.cfm'
  desc 'check', "1. Check to ensure the Enclave Authorizing Official (AO) has specifically documented the approval for use of KVM and/or A/B switches in the ATO or other official documentation signed by the AO authorizing use of switches between high-side (classified/SIPRNet) and low-side (unclassified/NIPRNet) shared devices.

2. Check to ensure the AO has submitted initial and updated documentation (as required) to the DoDIN Connection Approval Office (CAO) reflecting the use or addition of KVM or A/B devices on a user's enclave. The documentation may be part of the Authorization and Accreditation (A&A) documentation IAW RMF procedures or otherwise as specified by the DoDIN CAO.

3. Check to ensure SIPRNet enclaves also submit an updated SIPRNet Connection Questionnaire (SCQ) to the Connection Approval Office reflecting the device on the user's enclave - when new KVM or A/B switches are added.  

TACTICAL ENVIRONMENT: The check is applicable where KVM devices are in use."
  desc 'fix', "1. The Enclave Authorizing Official (AO) must specifically document the approval for use of KVM and/or A/B switches in the ATO or other official documentation signed by the AO authorizing use of switches between high-side (classified/SIPRNet) and low-side (unclassified/NIPRNet) shared devices.

2. The AO must submit initial and updated documentation (as required) to the DoDIN Connection Approval Office (CAO) reflecting the use or addition of KVM or A/B devices on a user's enclave. The documentation may be part of the Authorization and Accreditation (A&A) documentation IAW RMF procedures or otherwise as specified by the DoDIN CAO.

3. If using KVM on SIPRNet an updated SIPRNet Connection Questionnaire (SCQ) must be submitted to the Connection Approval Office reflecting the devices on the user's enclave - when new KVM or A/B switches are added."
  impact 0.3
  ref 'DPMS Target Traditional Security Checklist'
  tag check_id: 'C-49215r770012_chk'
  tag severity: 'low'
  tag gid: 'V-245784'
  tag rid: 'SV-245784r770014_rule'
  tag stig_id: 'IA-10.03.01'
  tag gtitle: 'IA-10.03.01'
  tag fix_id: 'F-49170r770013_fix'
  tag 'documentable'
  tag legacy: ['V-31126', 'SV-41267r3_rule']
end
