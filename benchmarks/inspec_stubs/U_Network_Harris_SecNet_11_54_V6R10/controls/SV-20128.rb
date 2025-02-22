control 'SV-20128' do
  title 'Physical security controls must be implemented for SWLAN access points.'
  desc 'If an adversary is able to gain physical access to a SWLAN device, it may be able to compromise the device in a variety of ways, some of which could enable the adversary to obtain classified data.  Physical security controls greatly mitigate this risk.'
  desc 'check', 'Detailed Policy Requirements:

The following physical security controls must be implemented for SWLAN access points:

- Secure WLAN access points shall be physically secured, and methods shall exist to facilitate the detection of tampering. WLAN APs are part of a communications system and shall have controlled physical security, in accordance with DoDD 5200.08-R. SWLAN access points not within a location that provides limited access shall have controlled physical security with either fencing or inspection.

- Either physical inventories or electronic inventories shall be conducted daily by viewing or polling the serial number or MAC address. Access points not stored in a COMSEC-approved security container shall be physically inventoried. 
Check Procedures:

It is recommended the Traditional Reviewer assist with this check. Review the physical security controls of the SWLAN access points.

- Verify site SWLAN access points are physically secured - -- Verify there is some method for alerting site security if the access point has been tampered with.
- Determine if site SWLAN access points are in locations that provide limited access to only authorized personnel who are approved to access the access points.
- Determine how the site conducts a daily physical inventory of SWLAN access points. Verify that required inventory methods are used, depending on if the access points are stored in a COMSEC container.

- Mark as a finding if any requirement has not been met.'
  desc 'fix', 'Implement required physical security controls for the SWLAN.'
  impact 0.5
  ref 'DPMS Target Harris Secnet 11'
  tag check_id: 'C-22007r1_chk'
  tag severity: 'medium'
  tag gid: 'V-18584'
  tag rid: 'SV-20128r1_rule'
  tag stig_id: 'WIR0225'
  tag gtitle: 'SWLAN physical security controls'
  tag fix_id: 'F-34120r1_fix'
  tag 'documentable'
  tag responsibility: ['Information Assurance Officer', 'System Administrator']
end
