control 'SV-256096' do
  title 'The Riverbed NetProfiler must be configured to conduct backups of system-level information and system documentation, including security-related documentation, when changes occur or weekly, whichever is sooner.'
  desc 'System-level information includes default and customized settings and security attributes, including access control lists (ACLs) that relate to the network device configuration, as well as software required for the execution and operation of the device. Information system backup is a critical step in ensuring system integrity and availability. If the system fails and there is no backup of the system-level information, a denial-of-service condition is possible for all who use this critical network component.

This control requires the network device to support the organizational central backup process for system-level information associated with the network device. This function may be provided by the network device itself; however, the preferred best practice is a centralized backup rather than each network device performing discrete backups. 

The backup feature securely copies traffic and configuration information to a specified backup system. NetProfiler cannot be configured to automatically run backups, but backups can be configured and run manually via the Backup page. Manually back up the system periodically in accordance with the site System Security Plan (SSP). NetExpress packet logs and index files are not backed up. Additionally, capture jobs are not restored if the backup and restore operations are performed from a physical NetExpress to a virtual edition or vice versa. The NetProfiler uses the SSH public key to connect to a backup server for running backups.

'
  desc 'check', "Review the SSP to determine the site's network device backup policy. 

Check the NetProfiler backup log to verify regular backups are being performed.

Go to System >> Backup.

View if there is a recent backup.

If the site does not conduct backups of system-level information contained in the information system when changes occur, this is a finding."
  desc 'fix', 'Manually back up via the configuration periodically in accordance with the SSP.

Go to System >> Backup. 

Enter details about what information must be backed up, where it is backed up, and who is notified when the backup is completed.

Click "Run Backup".'
  impact 0.3
  ref 'DPMS Target Riverbed NetProfiler'
  tag check_id: 'C-59770r882794_chk'
  tag severity: 'low'
  tag gid: 'V-256096'
  tag rid: 'SV-256096r882796_rule'
  tag stig_id: 'RINP-DM-000064'
  tag gtitle: 'SRG-APP-000516-NDM-000340'
  tag fix_id: 'F-59713r882795_fix'
  tag satisfies: ['SRG-APP-000516-NDM-000340', 'SRG-APP-000516-NDM-000341']
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-000537', 'CCI-000539']
  tag nist: ['CM-6 b', 'CP-9 (b)', 'CP-9 (c)']
end
