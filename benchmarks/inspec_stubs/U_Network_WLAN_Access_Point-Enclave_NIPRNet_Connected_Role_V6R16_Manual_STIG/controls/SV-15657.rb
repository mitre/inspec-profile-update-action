control 'SV-15657' do
  title 'WLAN signals must not be intercepted outside areas authorized for WLAN access.'
  desc 'Vulnerability Discussion: Most commercially-available WLAN equipment is pre-configured for signal power appropriate to most applications of the WLAN equipment.  In some cases, this may permit the signals to be received outside the physical areas for which they are intended.  This may occur when the intended area is relatively small, such as a conference room, or when the access point is placed near or window or wall, thereby allowing signals to be received in neighboring areas.  In such cases, an adversary may be able to compromise the site’s OPSEC posture by measuring the presence of the signal and the quantity of data transmitted to obtain information about when personnel are active and what they are doing.  Furthermore, if the signal is not appropriately protected through defense-in-depth mechanisms, the adversary could possibly use the connection to access DoD networks and sensitive information.'
  desc 'check', 'Review documentation and inspect AP locations.

1. Review documentation showing signal strength analysis from site survey activities, if available.  
2.  Use testing equipment or WLAN clients to determine if the signal strength is, in the reviewer’s judgment, excessively outside the required area (e.g., strong signal in the parking area, public areas, or uncontrolled spaces).  
3. Lower end APs will not have this setting available—in this case, the site should locate the APs away from exterior walls to achieve compliance with this requirement. 
4. Mark as a finding if any of the following is found.
o  Visual inspection of equipment shows obvious improper placement of APs where it will emanate into uncontrolled spaces (e.g., next to external walls, windows, or doors; uncontrolled areas;  or public areas).
o  Building walk-through testing shows signals of sufficient quality and strength to allow wireless access to exist in areas not authorized for WLAN access.'
  desc 'fix', 'Move APs to areas in which signals do not emanate in a manner making them usable outside the areas authorized for WLAN access.  Alternatively, replace omni-directional antennae with directional antennae if this will solve the problem.  If these solutions are not effective, then adjust the transmission power settings on the AP to reduce the usability of signals in unauthorized areas.  If the WLAN equipment does not allow the transmission power to be adjusted, and the APs are placed in a location where the IAO determines there is significant risk that an adversary could be present in location where signals may be intercepted, then the site should procure WLAN equipment that permits power adjustment.'
  impact 0.3
  ref 'DPMS Target Wireless Access Point'
  tag check_id: 'C-13418r1_chk'
  tag severity: 'low'
  tag gid: 'V-14889'
  tag rid: 'SV-15657r1_rule'
  tag stig_id: 'WIR0120'
  tag gtitle: 'Interception of WLAN signals'
  tag fix_id: 'F-3445r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
end
