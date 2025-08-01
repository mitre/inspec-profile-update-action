control 'SV-217422' do
  title 'The BIG-IP appliance must be configured to create backups of information system documentation, including security-related documentation, when changes occur or weekly, whichever is sooner.'
  desc 'Information system backup is a critical step in maintaining data assurance and availability. Information system and security-related documentation contains information pertaining to system configuration and security settings. If this information were not backed up and a system failure were to occur, the security settings would be difficult to reconfigure quickly and accurately. Maintaining a backup of information system and security-related documentation provides for a quicker recovery time when system outages occur.

This control requires the network device to support the organizational central backup process for user account information associated with the network device. This function may be provided by the network device itself; however, the preferred best practice is a centralized backup rather than each network device performing discrete backups.'
  desc 'check', 'Verify the BIG-IP appliance is configured to off-load logs to a remote log server when changes occur.

Navigate to the BIG-IP System manager >> System >> Logs >> Configuration >> Remote Logging.

Verify a log destination is configured to allow for backups of information system documentation when changes occur.

If the BIG-IP appliance does not backup the information system documentation, including security-related documentation, when changes occur, this is a finding.'
  desc 'fix', 'Configure the BIG-IP appliance to create backups of information system documentation, including security-related documentation, when changes occur.'
  impact 0.5
  ref 'DPMS Target F5 BIG-IP Device Management 11.x'
  tag check_id: 'C-18647r290820_chk'
  tag severity: 'medium'
  tag gid: 'V-217422'
  tag rid: 'SV-217422r879887_rule'
  tag stig_id: 'F5BI-DM-000279'
  tag gtitle: 'SRG-APP-000516-NDM-000341'
  tag fix_id: 'F-18645r290821_fix'
  tag 'documentable'
  tag legacy: ['SV-74665', 'V-60235']
  tag cci: ['CCI-000539', 'CCI-000366']
  tag nist: ['CP-9 (c)', 'CM-6 b']
end
