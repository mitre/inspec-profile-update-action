control 'SV-41259' do
  title 'Information Assurance - KVM Switch (Port Separation) on CYBEX/Avocent 4 or 8 port'
  desc 'The back plate of some 4 or 8 port CYBEX/AVOCENT KVM devices  provides a physical connection between adjacent ports.  Therefore failure to provide for physical port separation between SIPRNet (classified devices) and NIPRNet (unclassified devices) when using  CYBEX/AVOCENT KVM devices  can result in the loss or compromise of classified information.

REFERENCES:

Keyboard, Video, Mouse Switch Security STIG 

DISN Peripheral Sharing Device Guidance: Defense IA/Security Accreditation Working Group (DSAWG) August 2009 - NOTE the DSAWG Meeting Minutes that published KVM guidance were originally from 2006 and last updated in May 2014 - but retains an August 2009 date on the cover of the Power Point slides.

NIST Special Publication 800-53 (SP 800-53), Rev 4, Controls: 
SC-3 and SC-4

DISN Connection Process Guide:
http://disa.mil/network-services/enterprise-connections/connection-process-guide

NIAP Products Compliance List (PCL):
https://www.niap-ccevs.org/index.cfm'
  desc 'check', 'Validate the correct configuration of CYBEX/Avocent 4 or 8 port KVMs IAW DSAWG guidance.  This includes physical port separation between SIPRNet and NIPRNet (high & low) connections. Because of the internal physical configuration of the CYBEX boxes, only like classification levels may be connected to adjacent ports. 

This is based on slide #6 of the DSAWG KVM guidance. Any variation to this guidance must be presented to the DSAWG for review and approved before implementation. 

TACTICAL ENVIRONMENT: The check is applicable where KVM devices are in use.'
  desc 'fix', '1. CYBEX/Avocent 4 or 8 port KVMs used for switching devices between the SIPRNet and NIPRNet (or any switching between SIPRNet and any other unclassified network devices) must be correctly configured IAW DSAWG guidance. 

2. Correct configuration must include physical port separation between SIPRNet and NIPRNet (high & low) (or any switching between SIPRNet and any other unclassified network devices) connections. 

3. Because of the internal physical configuration of the CYBEX/Avocent box back plates, only like classification levels may be connected to adjacent ports. 

NOTE: This is based on slide #6 of the DSAWG KVM guidance.  Any variation to this guidance must be presented to the DSAWG for review and approved before implementation.'
  impact 0.5
  ref 'DPMS Target Traditional Security'
  tag check_id: 'C-39804r4_chk'
  tag severity: 'medium'
  tag gid: 'V-31124'
  tag rid: 'SV-41259r4_rule'
  tag stig_id: 'IA-10.02.02'
  tag gtitle: 'Information Assurance - KVM Switch (Port Separation)'
  tag fix_id: 'F-35002r4_fix'
  tag 'documentable'
end
