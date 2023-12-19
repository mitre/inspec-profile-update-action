control 'SV-242637' do
  title 'The Cisco ISE must be configured to conduct backups of system level information contained in the information system when changes occur.'
  desc 'System-level information includes default and customized settings and security attributes, including ACLs that relate to the network device configuration, as well as software required for the execution and operation of the device. Information system backup is a critical step in ensuring system integrity and availability. If the system fails and there is no backup of the system-level information, a denial of service condition is possible for all who utilize this critical network component.

This control requires the network device to support the organizational central backup process for system-level information associated with the network device. This function may be provided by the network device itself; however, the preferred best practice is a centralized backup rather than each network device performing discrete backups.

The Cisco ISE uses the CLI backup command to backup of system level information. However, the best practice is to use configuration backup products such as Tivoli, NCM, and FCM. Configuration for the backup is accomplished on the backup device, not on the Cisco. These products can be configured to either backup all files or just the rollback files which are saved each time a commit is executed.

Save changes made to the running configuration to the startup configurations these changes will not be lost when the system is restarted.'
  desc 'check', "1. Review the SSP to see the site's network device backup policy. Check the Cisco ISE backup log to verify regular backups are being performed.
show backup history
2. Determine if there is a recent history of backups.

If the Cisco ISE is not configured to conduct backups of system-level information contained in the information system when changes occur, this is a finding."
  desc 'fix', 'Save changes made to the startup configuration.

copy running-config startup-config

To save changes to the Cisco ISE configuration and/or Cisco ADE OS data and place the backup in a repository, use the backup command in EXEC mode on the CLI.

backup [{backup-name} repository {repository-name} ise-operational encryption-key hash| plain {encryption-key name}]'
  impact 0.5
  ref 'DPMS Target Cisco ISE NDM'
  tag check_id: 'C-45912r714219_chk'
  tag severity: 'medium'
  tag gid: 'V-242637'
  tag rid: 'SV-242637r714221_rule'
  tag stig_id: 'CSCO-NM-000320'
  tag gtitle: 'SRG-APP-000516-NDM-000340'
  tag fix_id: 'F-45869r714220_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-000537']
  tag nist: ['CM-6 b', 'CP-9 (b)']
end
