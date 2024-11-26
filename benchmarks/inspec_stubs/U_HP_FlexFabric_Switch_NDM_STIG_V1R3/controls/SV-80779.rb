control 'SV-80779' do
  title 'The HP FlexFabric Switch must support organizational requirements to conduct backups of system level information contained in the information system when changes occur or weekly, whichever is sooner.'
  desc 'System-level information includes default and customized settings and security attributes, including ACLs that relate to the HP FlexFabric Switch configuration, as well as software required for the execution and operation of the device. Information system backup is a critical step in ensuring system integrity and availability. If the system fails and there is no backup of the system-level information, a denial of service condition is possible for all who utilize this critical network component.

This control requires the HP FlexFabric Switch to support the organizational central backup process for system-level information associated with the HP FlexFabric Switch. This function may be provided by the HP FlexFabric Switch itself; however, the preferred best practice is a centralized backup rather than each network device performing discrete backups.'
  desc 'check', 'Review the HP FlexFabric Switch configuration to determine if it is configured to back up its configuration file on a weekly basis.

If a schedule does not exist, this is a finding.

[HP] display scheduler job

Job name: system_backup
tftp 192.168.1.13 put hp5900.cfg'
  desc 'fix', 'Configure the HP FlexFabric Switch to back up its configuration to a TFTP/FTP server:

[HP] scheduler job config_backup
[HP-job-config_backup] command 1 tftp 15.252.76.13 put 5900.cfg [HP-job-config_backup] quit [HP] scheduler schedule 5900-backup [HP-schedule-5900-backup] user-role network-admin [HP-schedule-5900-backup]  job test [HP-schedule-5900-backup]  time repeating at 14:14 week-day Thu'
  impact 0.3
  ref 'DPMS Target HP Flex Fabric Switch 7 NDM'
  tag check_id: 'C-66935r1_chk'
  tag severity: 'low'
  tag gid: 'V-66289'
  tag rid: 'SV-80779r1_rule'
  tag stig_id: 'HFFS-ND-000137'
  tag gtitle: 'SRG-APP-000516-NDM-000340'
  tag fix_id: 'F-72365r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-000537']
  tag nist: ['CM-6 b', 'CP-9 (b)']
end
