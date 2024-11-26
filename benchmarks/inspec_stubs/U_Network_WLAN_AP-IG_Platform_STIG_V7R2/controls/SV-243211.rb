control 'SV-243211' do
  title 'WLAN signals must not be intercepted outside areas authorized for WLAN access.'
  desc "Most commercially available WLAN equipment is preconfigured for signal power appropriate to most applications of the WLAN equipment. In some cases, this may permit the signals to be received outside the physical areas for which they are intended. This can occur when the intended area is relatively small, such as a conference room, or when the access point is placed near or window or wall, thereby allowing signals to be received in neighboring areas. 

In such cases, an adversary may be able to compromise the site's posture by measuring the presence of the signal and the quantity of data transmitted to obtain information about when personnel are active and what they are doing. If the signal is not appropriately protected through defense-in-depth mechanisms, the adversary could possibly use the connection to access DoD networks and sensitive information."
  desc 'check', "Review documentation and inspect access point locations.

1. Review documentation showing signal strength analysis from site survey activities, if available.
2. Use testing equipment or WLAN clients to determine if the signal strength is, in the reviewer's judgment, excessively outside the required area (e.g., strong signal in the parking area, public areas, or uncontrolled spaces).
3. Lower-end access points will not have this setting available. In this case, verify the access points are located away from exterior walls to achieve compliance with this requirement.

If any of the following is found, this is a finding:
- Visual inspection of equipment shows obvious improper placement of access points where they will emanate into uncontrolled spaces (e.g., next to external walls, windows, or doors; uncontrolled areas; or public areas).
- Building walk-through testing shows signals of sufficient quality and strength to allow wireless access to exist in areas not authorized for WLAN access."
  desc 'fix', 'Move access points to areas in which signals do not emanate in a way that makes them usable outside the areas authorized for WLAN access.

Alternatively, replace omni-directional antennae with directional antennae if this will solve the problem.

If these solutions are not effective, adjust the transmission power settings on the access point to reduce the usability of signals in unauthorized areas.

If the WLAN equipment does not allow the transmission power to be adjusted, and the access points are placed in a location where the ISSO determines there is significant risk that an adversary could be present where signals may be intercepted, the site should procure WLAN equipment that permits power adjustment.'
  impact 0.3
  ref 'DPMS Target Network WLAN AP-IG Platform'
  tag check_id: 'C-46486r720086_chk'
  tag severity: 'low'
  tag gid: 'V-243211'
  tag rid: 'SV-243211r720088_rule'
  tag stig_id: 'WLAN-NW-000800'
  tag gtitle: 'SRG-NET-000384'
  tag fix_id: 'F-46443r720087_fix'
  tag 'documentable'
  tag cci: ['CCI-002683']
  tag nist: ['SI-4 (22) (a)']
end
