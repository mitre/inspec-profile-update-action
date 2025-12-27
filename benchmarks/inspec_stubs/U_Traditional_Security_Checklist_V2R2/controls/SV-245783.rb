control 'SV-245783' do
  title 'Information Assurance - KVM Switch Use of Hot-Keys on SIPRNet Connected Devices'
  desc 'Use of "Hot Keys" for switching between devices relies on use of software to separate and switch between the devices.  Unless software use involves an approved Cross Domain Solution (CDS) it can result in the loss or compromise of classified information from low side devices to those devices on the high side.  Only physical switching between devices can assure that information will not be exchanged.

REFERENCES:

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
  ref 'DPMS Target Traditional Security Checklist'
  tag check_id: 'C-49214r770009_chk'
  tag severity: 'medium'
  tag gid: 'V-245783'
  tag rid: 'SV-245783r863300_rule'
  tag stig_id: 'IA-10.02.03'
  tag gtitle: 'IA-10.02.03'
  tag fix_id: 'F-49169r770010_fix'
  tag 'documentable'
  tag legacy: ['V-31125', 'SV-41260r3_rule']
end
