control 'SV-77441' do
  title 'Riverbed Optimization System (RiOS) must back up the system configuration files when configuration changes are made to the device.'
  desc 'Information system backup is a critical step in maintaining data assurance and availability. Information system and security-related documentation contains information pertaining to system configuration and security settings. If this information were not backed up, and a system failure were to occur, the security settings would be difficult to reconfigure quickly and accurately. Maintaining a backup of information system and security-related documentation provides for a quicker recovery time when system outages occur.

This control requires the network device to support the organizational central backup process for user account information associated with the network device. This function may be provided by the network device itself; however, the preferred best practice is a centralized backup rather than each network device performing discrete backups.'
  desc 'check', 'Verify that RiOS is backed up when system configuration changes are made to the device by interviewing the site representative and checking any existing backup log. Evidence may also be provided by the date of the last back up.

Navigate to the device Management Console
Navigate to Configure >> Configurations

Verify that the table for "Configuration" and "Date" contains backup configurations

If there are no entries under "Configuration" and "Date", this is a finding.'
  desc 'fix', 'When changes are made to the system configuration, using the following procedure for backing up the device.

Navigate to the device Management Console
Navigate to Configure >> Configurations
Set the value of "New Configuration Name:" to the naming standards for the organization backups
Click "Save"

Verify that the saved configuration shows up under "Configuration" and the "Date" is the current date and time'
  impact 0.5
  ref 'DPMS Target Riverbed SteelHead CX Version 8 NDM'
  tag check_id: 'C-63703r1_chk'
  tag severity: 'medium'
  tag gid: 'V-62951'
  tag rid: 'SV-77441r1_rule'
  tag stig_id: 'RICX-DM-000100'
  tag gtitle: 'SRG-APP-000516-NDM-000341'
  tag fix_id: 'F-68869r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-000539']
  tag nist: ['CM-6 b', 'CP-9 (c)']
end
