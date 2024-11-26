control 'SV-31260' do
  title 'The PDA/smartphone must be configured to require a passcode for device unlock.'
  desc 'Sensitive DoD data could be compromised if a device unlock passcode is not set up on a DoD PDA/smartphone. These devices are particularly vulnerable because they are exposed to many potential adversaries when they taken outside of the physical security perimeter of DoD facilities, and because they are easily concealed if stolen.'
  desc 'check', 'Detailed Policy Requirements:  

PDAs and smartphones must be protected by authenticated login procedures to unlock the device.  Either CAC or password authentication is required. 

Check Procedures:  
Interview the IAO and system administrator.   
- Verify that CAC authentication or password authentication is used on site managed PDAs.  Verify authentication is required to unlock the PDA on a sample of devices at the site.  Inspect 3-4 devices.'
  desc 'fix', 'Configure the MDM server to require a passcode for device unlock.'
  impact 0.7
  ref 'DPMS Target PDA/PED'
  tag check_id: 'C-31668r1_chk'
  tag severity: 'high'
  tag gid: 'V-25007'
  tag rid: 'SV-31260r1_rule'
  tag stig_id: 'WIR-MOS-PDA-010'
  tag gtitle: 'Require device unlock password/passcode'
  tag fix_id: 'F-27657r3_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECWN-1, IAIA-1'
end
