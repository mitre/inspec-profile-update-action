control 'SV-7015' do
  title 'Print services for a MFD or printer are not restricted to Port 9100 and/or LPD (Port 515).

Where both Windows and non-Windows clients need services from the same device, both Port 9100 and LPD can be enabled simultaneously.'
  desc 'Printer services running on ports other than the known ports for printing cannot be monitored on the network and could lead to a denial of service it the invalid port is blocked by a network administrator responding to an alert from the IDS for traffic on an unauthorized port.'
  desc 'check', 'The reviewer will, with the assistance of the SA, verify that the MFD or printer print services are restricted to LPD or port 9100.

Where both Windows and non-Windows clients need services from the same device, both Port 9100 and LPD can be enabled simultaneously.'
  desc 'fix', 'Develop a plan to coordinate the reconfiguration of the printer servers and clients so that print services runs only on authorized ports.  Obtain CM approval of the plan and implement the plan.'
  impact 0.3
  ref 'DPMS Target Multifunction Device - MFD'
  tag check_id: 'C-2994r1_chk'
  tag severity: 'low'
  tag gid: 'V-6790'
  tag rid: 'SV-7015r1_rule'
  tag stig_id: 'MFD03.001'
  tag gtitle: 'Print Services Restricted to Port 9100 and/or LPD'
  tag fix_id: 'F-6456r1_fix'
  tag 'documentable'
  tag potential_impacts: 'Print clients configured to use the unauthorized port(s) will not be able to print until they are reconfigured to use the correct port.'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'DCBP-1'
end
