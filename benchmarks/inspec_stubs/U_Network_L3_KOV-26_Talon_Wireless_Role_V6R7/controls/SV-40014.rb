control 'SV-40014' do
  title 'SWLAN access points must implement MAC filtering.'
  desc 'Medium access control (MAC) filtering is a mechanism for ensuring that only authorized devices connect to the WLAN.  While there are other methods to achieve similar protection with greater assurance, MAC filtering can be employed as a defense-in-depth measure.'
  desc 'check', 'Detailed Policy Requirements:

MAC filtering must be implemented to enable the SWLAN AP to perform client device access control. 

Check Procedures:

Verify MAC address filtering has been implemented on site SWLAN access points. Have the system administrator log into a sample of site SWLAN access points (2-3 devices) and show MAC address filtering has been enabled. 
Mark as a finding if MAC filtering has not been enabled.'
  desc 'fix', 'Implement MAC filtering on the SWLAN access point.'
  impact 0.3
  ref 'DPMS Target L3 KOV-26 Talon'
  tag check_id: 'C-39028r1_chk'
  tag severity: 'low'
  tag gid: 'V-30359'
  tag rid: 'SV-40014r1_rule'
  tag stig_id: 'WIR0226'
  tag gtitle: 'SWLAN MAC Filtering'
  tag fix_id: 'F-34123r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag ia_controls: 'ECWN-1'
end
