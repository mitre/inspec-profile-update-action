control 'SV-242638' do
  title 'The Cisco ISE must conduct backups of information system documentation, including security-related configuration files when changes occur or weekly, whichever is sooner.'
  desc 'Information system backup is a critical step in maintaining data assurance and availability. Information system and security-related documentation contains information pertaining to system configuration and security settings. If this information was not backed up and a system failure was to occur, the security settings would be difficult to reconfigure quickly and accurately. Maintaining a backup of information system and security-related documentation provides for a quicker recovery time when system outages occur.

This control requires the network device to support the organizational central backup process for user account information associated with the network device. This function may be provided by the network device itself; however, the preferred best practice is a centralized backup rather than each network device performing discrete backups.'
  desc 'check', "1. Review the SSP to see the site's network device backup policy. Check the Cisco ISE backup log to verify regular backups are being performed.
show backup history
2. Determine if there is a recent history of backups. Verify if the backup history shows either weekly backups or periodic backups.

If the Cisco ISE is not configured to conduct backups of system-level information contained in the information system when changes occur, this is a finding."
  desc 'fix', 'Save changes to the Cisco ISE configuration files data and place the backup in a repository by using the backup command in EXEC mode on the CLI.

backup [{backup-name} repository {repository-name} ise-config encryption-key hash| plain {encryption-key name}]'
  impact 0.3
  ref 'DPMS Target Cisco ISE NDM'
  tag check_id: 'C-45913r714222_chk'
  tag severity: 'low'
  tag gid: 'V-242638'
  tag rid: 'SV-242638r879887_rule'
  tag stig_id: 'CSCO-NM-000330'
  tag gtitle: 'SRG-APP-000516-NDM-000341'
  tag fix_id: 'F-45870r714223_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-000539']
  tag nist: ['CM-6 b', 'CP-9 (c)']
end
