control 'SV-30699' do
  title 'The site Incident Response Plan or other procedure must include procedures to follow when a mobile operating system (OS) based mobile device is reported lost or stolen.'
  desc 'Sensitive DoD data could be stored in memory on a DoD operated mobile operating system (OS) based CMD and the data could be compromised if required actions are not followed when a CMD is lost or stolen. Without procedures for lost or stolen mobile operating system (OS) based CMD devices, it is more likely that an adversary could obtain the device and use it to access DoD networks or otherwise compromise DoD IA.'
  desc 'check', 'Detailed Policy Requirements: 

The site (location where CMDs are issued and managed and the site where the mobile operating system (OS) based CMD management server is located) must publish procedures to follow if a CMD has been lost or stolen. The procedures should include (as appropriate):

-Mobile device user notifies IAO, SM, and other site personnel, as required by the site’s Incident Response Plan, within the timeframe required by the site’s Incident Response Plan. 

-The IAO notifies the mobile device management server system administrator and other site personnel, as required by the site’s Incident Response Plan, within the timeframe required by the site’s Incident Response Plan. 

The site mobile device management server administrator sends a wipe command to the CMD and then disables the user account on the management server or removes the CMD from the user account.

-The site will contact the carrier to have the device deactivated on the carrier’s network.

Check procedures: 
Interview the IAO. 

Review the site’s Incident Response Plan or other policies and determine if the site has a written plan of action.

Mark as a finding if the site does not have a written plan of action following a lost or stolen CMD.'
  desc 'fix', 'Publish procedures to follow if a mobile operating system (OS) based CMD is lost or stolen.'
  impact 0.3
  ref 'DPMS Target CSfC Policy - WLAN CP'
  tag check_id: 'C-31122r4_chk'
  tag severity: 'low'
  tag gid: 'V-24962'
  tag rid: 'SV-30699r4_rule'
  tag stig_id: 'WIR-SPP-007-01'
  tag gtitle: 'Publish lost/stolen CMD procedures'
  tag fix_id: 'F-27603r2_fix'
  tag 'documentable'
  tag responsibility: 'Information Assurance Officer'
  tag ia_controls: 'ECSC-1, VIIR-1, VIIR-2'
end
