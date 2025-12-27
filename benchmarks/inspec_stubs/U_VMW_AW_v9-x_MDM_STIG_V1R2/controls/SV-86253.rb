control 'SV-86253' do
  title 'The AirWatch MDM Agent must be configured for the periodicity of reachability events for six hours or less.'
  desc 'Mobile devices that do not enforce security policy or verify the status of the device are vulnerable to a variety of attacks. The key security function of MDM technology is to distribute mobile device security polices in such a manner that they are enforced on managed mobile devices. To accomplish this function, the AirWatch MDM Agent must verify the status and other key information of the managed device and report that status to the MDM server periodically.

SFR ID: FMT_SMF_EXT.3.2'
  desc 'check', %q(Review the AirWatch MDM Agent documentation and configuration settings to determine if the periodicity of reachable events is set to six hours or less.

On the AirWatch console complete the following procedure:

1. Log into the AirWatch MDM Administration console.
2. Choose "Groups and Settings".
3. Choose "All Settings".
4. Choose "Devices and Users".
5. Choose "Android".
6. Choose "Agent Settings".
7. Verify that options "Heartbeat Interval", "Data Sample Interval", "Data Transmit Interval", "Profile Refresh Interval", and "Application List Interval" are set to six hours or less.
8. Choose "Apple".
9. Choose "MDM Sample Schedule".
10. Verify that options "Device Information Sample", "Application List Sample", "Certificate List Sample", "Profile List Sample", 'Provisioning Profile List Sample", "Restriction List Sample", "Security Information Sample", "Managed App List Sample", "MDM Agent Sample", and "Non-Compliant Device Sample" are set to six hours or less.

If on the AirWatch console the above noted settings are not configured to six hours or less, this is a finding.)
  desc 'fix', %q(Configure the AirWatch MDM Agent periodicity of reachable events to six hours or less.

On the AirWatch console do the following: 

1. Log into the AirWatch MDM Administration console.
2. Choose "Groups and Settings".
3. Choose "All Settings".
4. Choose "Devices and Users".
5. Choose "Android".
6. Choose "Agent Settings".
7. Set options "Heartbeat Interval", "Data Sample Interval", "Data Transmit Interval", "Profile Refresh Interval", and "Application List Interval" to six hours or less.
8.Click "Save".
9. Choose "Apple".
10. Choose "MDM Sample Schedule".
11. Set options "Device Information Sample", "Application List Sample", "Certificate List Sample", "Profile List Sample", 'Provisioning Profile List Sample", "Restriction List Sample", "Security Information Sample", "Managed App List Sample", "MDM Agent Sample", and "Non-Compliant Device Sample" to six hours or less.
12. Click "Save".)
  impact 0.3
  ref 'DPMS Target AirWatch MDM 9.x'
  tag check_id: 'C-71959r2_chk'
  tag severity: 'low'
  tag gid: 'V-71629'
  tag rid: 'SV-86253r1_rule'
  tag stig_id: 'VMAW-09-100010'
  tag gtitle: 'PP-MDM-201101'
  tag fix_id: 'F-77955r3_fix'
  tag 'documentable'
  tag cci: ['CCI-002696']
  tag nist: ['SI-6 a']
end
