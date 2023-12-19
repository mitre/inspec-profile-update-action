control 'SV-41260' do
  title 'Information Assurance - KVM Switch Use of Hot-Keys on SIPRNet Connected Devices'
  desc 'Use of "Hot Keys" for switching between devices relies on use of software to separate and switch between the devices.  Unless software use involves an approved Cross Domain Solution (CDS) it can result in the loss or compromise of classified information from low side devices to those devices on the high side.  Only physical switching between devices can assure that information will not be exchanged.

REFERENCES:

Keyboard, Video, Mouse Switch Security STIG 

DISN Peripheral Sharing Device Guidance: Defense IA/Security Accreditation Working Group (DSAWG) August 2009 - NOTE the DSAWG Meeting Minutes that published KVM guidance were originally from 2006 and last updated in May 2014 - but retains an August 2009 date on the cover of the Power Point slides.

NIST Special Publication 800-53 (SP 800-53), Rev 4, Controls: 
SC-3 and SC-4

DISN Connection Process Guide:
http://disa.mil/network-services/enterprise-connections/connection-process-guide

NIAP Products Compliance List (PCL):
https://www.niap-ccevs.org/index.cfm'
  desc 'check', '1. Check to ensure users are physically switching between devices on SIPRNet and any devices connected to an unclassified network like NIPRNet, rather than using a Hot-Key feature. 

2. Be suspicious of any KVM that is not easily reachable (within arms distance) by the keyboard operator. 

TACTICAL ENVIRONMENT: The check is applicable where KVM devices are in use.'
  desc 'fix', 'Users of KVM devices must physically switch between devices connected to the SIPRNet and any devices connected to an Unclassified network such as NIPRNet, rather than using a Hot-Key feature.'
  impact 0.5
  ref 'DPMS Target Traditional Security'
  tag check_id: 'C-39805r3_chk'
  tag severity: 'medium'
  tag gid: 'V-31125'
  tag rid: 'SV-41260r3_rule'
  tag stig_id: 'IA-10.02.03'
  tag gtitle: 'Information Assurance - KVM Switch (Hot-Keys)'
  tag fix_id: 'F-35008r4_fix'
  tag 'documentable'
end
