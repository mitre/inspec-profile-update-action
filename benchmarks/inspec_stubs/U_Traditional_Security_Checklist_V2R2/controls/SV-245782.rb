control 'SV-245782' do
  title 'Information Assurance - KVM Switch (Port Separation) on CYBEX/Avocent 4 or 8 port'
  desc 'The back plate of some 4 or 8 port CYBEX/AVOCENT KVM devices  provides a physical connection between adjacent ports.  Therefore failure to provide for physical port separation between SIPRNet (classified devices) and NIPRNet (unclassified devices) when using  CYBEX/AVOCENT KVM devices  can result in the loss or compromise of classified information.

REFERENCES:

NIST Special Publication 800-53 (SP 800-53), Rev 4, Controls: 
SC-3 and SC-4

DISN Connection Process Guide:
http://disa.mil/network-services/enterprise-connections/connection-process-guide

NIAP Products Compliance List (PCL):
https://www.niap-ccevs.org/index.cfm'
  desc 'check', 'Validate the correct configuration of CYBEX/Avocent 4 or 8 port KVMs IAW NIAP/APL guidance. This includes physical port separation between SIPRNet and NIPRNet (high & low) connections. Because of the internal physical configuration of the CYBEX boxes, only like classification levels may be connected to adjacent ports. 

TACTICAL ENVIRONMENT: The check is applicable where KVM devices are in use.'
  desc 'fix', '1. Validate the correct configuration of CYBEX/Avocent 4 or 8 port KVMs used for switching devices between the SIPRNet and NIPRNet (or any switching between SIPRNet and any other unclassified network devices) must be correctly configured IAW NIAP/APL guidance.

2. Correct configuration must include physical port separation between SIPRNet and NIPRNet (high & low) (or any switching between SIPRNet and any other unclassified network devices) connections.

3. Because of the internal physical configuration of the CYBEX/Avocent box backplates, only like classification levels may be connected to adjacent ports.'
  impact 0.5
  ref 'DPMS Target Traditional Security Checklist'
  tag check_id: 'C-49213r865847_chk'
  tag severity: 'medium'
  tag gid: 'V-245782'
  tag rid: 'SV-245782r865849_rule'
  tag stig_id: 'IA-10.02.02'
  tag gtitle: 'IA-10.02.02'
  tag fix_id: 'F-49168r865848_fix'
  tag 'documentable'
  tag legacy: ['V-31124', 'SV-41259r4_rule']
end
