control 'SV-8779' do
  title 'The site IAO must maintain a list of all DAA-approved wireless and non-wireless PED devices that store, process, or transmit DoD information.'
  desc 'The site must maintain a list of all DAA-approved wireless and non-wireless CMDs. Close tracking of authorized wireless devices will facilitate the search for rogue devices. Sites must keep good inventory control over wireless and handheld devices used to store, process, and transmit DoD data since these devices can be easily lost or stolen leading to possible exposure of DoD data.'
  desc 'check', 'Detailed Policy Requirements:

This check applies to any wireless end user device (smartphone, tablet, Wi-Fi network interface card, etc.) and wireless network devices (access point, authentication server, etc.). The list of approved wireless devices will be stored in a secure location and will include the following at a minimum:
- Access point Media Access Control (MAC) address (WLAN only),
- Access point IP address (WLAN only),
- Wireless client MAC address,
- Network DHCP range (WLAN & WWAN only),
- Type of encryption enabled,
- Access point SSID (WLAN only),
- Manufacturer, model number, and serial number of wireless equipment,
- Equipment location, and
- Assigned users with telephone numbers.

For  CMDs:
- Manufacturer, model number, and serial number of wireless equipment.
- Equipment location or who the device was issued to.
- Assigned users with telephone numbers and email addresses.

For SME PED:
Local commands will keep track of devices by assigning a control number or using the serial number for accountability purposes.

Check Procedures:

Work with the site POC: 
1. Request copies of site’s wireless equipment list. 
-Detailed SSAA/SSP or database may be used. 
2. Verify all minimum data elements listed above are included in the equipment list. 
3. Verify all wireless devices used at the site, including infrared mice/keyboards, are included. 
4. Verify procedures are in place for ensuring the list is kept updated. 
5. Note the date of last update and if the list has many inaccuracies. 
Mark as a finding if the equipment list does not exist, all data elements are not tracked, or the list is outdated.

This check applies to: 
- Wireless networking devices, such as access points, bridges, and switches.
- WLAN client devices, such as laptop computers and PDAs if used with WLAN NICs.
- Wireless peripherals, such as Bluetooth, and Infrared mice and keyboards, communications devices, such as VoIP, cellular/satellite telephones, and Broadband NICs, and non-wireless CMDs that store, process, or transmit DoD information.'
  desc 'fix', 'Maintain a list of all DAA-approved WLAN devices.  The list must be updated periodically and will contain the data elements required by the STIG policy.'
  impact 0.3
  ref 'DPMS Target CSfC Policy - WLAN CP'
  tag check_id: 'C-7600r4_chk'
  tag severity: 'low'
  tag gid: 'V-8284'
  tag rid: 'SV-8779r6_rule'
  tag stig_id: 'WIR0015'
  tag gtitle: 'Site list of approved CMDs'
  tag fix_id: 'F-3728r2_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag ia_controls: 'DCHW-1'
end
