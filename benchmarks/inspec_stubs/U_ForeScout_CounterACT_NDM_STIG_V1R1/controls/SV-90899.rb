control 'SV-90899' do
  title 'CounterACT must support organizational requirements to conduct backups of information system documentation, including security-related documentation, when changes occur or weekly, whichever is sooner.'
  desc 'Information system backup is a critical step in maintaining data assurance and availability. Information system and security-related documentation contains information pertaining to system configuration and security settings. If this information were not backed up, and a system failure were to occur, the security settings would be difficult to reconfigure quickly and accurately. Maintaining a backup of information system and security-related documentation provides for a quicker recovery time when system outages occur.

This control requires the network device to support the organizational central backup process for user account information associated with the network device. This function may be provided by the network device itself; however, the preferred best practice is a centralized backup rather than each network device performing discrete backups.'
  desc 'check', 'Review the CounterACT backup configuration to determine if the network device backs up the information system documentation, including security-related documentation, when changes occur or weekly, whichever is sooner.

1. Open the CounterACT Console and select Tools >> Options.
2. Select the "+" next to "Advanced" menu (toward the bottom).
3. Select the “Backup” submenu.
4. On the “System Backup” tab, verify the "Enable System Backup" radio button is selected.
5. Verify the Backup schedule is selected to at least "weekly".

If the network device does not back up the information system documentation, including security-related documentation, when changes occur or weekly, whichever is sooner, this is a finding.'
  desc 'fix', 'Configure CounterACT to conduct backups of information system documentation, including security-related documentation, when changes occur or weekly, whichever is sooner.

1. Open the CounterACT Console and select Tools >> Options.
2. Select the "+" next to "Advanced" menu (toward the bottom).
3. Select the “Backup” submenu.
4. On the “System Backup” tab, ensure the "Enable System Backup" radio button is selected.
5. Ensure the Backup schedule is selected to at least "weekly".'
  impact 0.3
  ref 'DPMS Target ForeScout CounterACT NDM'
  tag check_id: 'C-75897r1_chk'
  tag severity: 'low'
  tag gid: 'V-76211'
  tag rid: 'SV-90899r1_rule'
  tag stig_id: 'CACT-NM-000014'
  tag gtitle: 'SRG-APP-000516-NDM-000341'
  tag fix_id: 'F-82847r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-000539']
  tag nist: ['CM-6 b', 'CP-9 (c)']
end
