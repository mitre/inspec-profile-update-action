control 'SV-242637' do
  title 'The Cisco ISE must be configured to conduct backups of system level information contained in the information system when changes occur.'
  desc 'System-level information includes default and customized settings and security attributes, including ACLs that relate to the network device configuration, as well as software required for the execution and operation of the device. Information system backup is a critical step in ensuring system integrity and availability. If the system fails and there is no backup of the system-level information, a denial of service condition is possible for all who utilize this critical network component.

This control requires the network device to support the organizational central backup process for system-level information associated with the network device. This function may be provided by the network device itself; however, the preferred best practice is a centralized backup rather than each network device performing discrete backups.

The Cisco ISE uses the CLI backup command to backup of system level information. However, the best practice is to use configuration backup products such as Tivoli, NCM, and FCM. Configuration for the backup is accomplished on the backup device, not on the Cisco. These products can be configured to either backup all files or just the rollback files which are saved each time a commit is executed.

Save changes made to the running configuration to the startup configurations these changes will not be lost when the system is restarted.'
  desc 'check', "Navigate to Administration >> System >> Backup and Restore.

Ensure that configuration data backups are scheduled for weekly intervals or in accordance with the site's SSP.

If backups of the confiuration data are not made when when changes occur or in accordance with the site's SSP, this is a finding."
  desc 'fix', %q(Navigate to Administration >> System >> Backup and Restore. 

1. Select the "Schedule" option next to configuration Data Backup.
2. Ensure a weekly scheduled backup is configured (or in accordance with the site's SSP).)
  impact 0.5
  ref 'DPMS Target Cisco ISE NDM'
  tag check_id: 'C-45912r803577_chk'
  tag severity: 'medium'
  tag gid: 'V-242637'
  tag rid: 'SV-242637r803579_rule'
  tag stig_id: 'CSCO-NM-000320'
  tag gtitle: 'SRG-APP-000516-NDM-000340'
  tag fix_id: 'F-45869r803578_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-000537']
  tag nist: ['CM-6 b', 'CP-9 (b)']
end
