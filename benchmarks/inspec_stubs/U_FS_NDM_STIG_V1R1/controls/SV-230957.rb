control 'SV-230957' do
  title 'Forescout must support organizational requirements to conduct backups of information system documentation, including security-related documentation, when changes occur or weekly, whichever is sooner.'
  desc 'System-level information includes default and customized settings and security attributes, including ACLs that relate to the network device configuration, as well as software required for the execution and operation of the device. Information system backup is a critical step in ensuring system integrity and availability. If the system fails and there is no backup of the system-level information, a denial-of-service condition is possible for all who utilize this critical network component.

Perform scheduled backups of the Forescout system to FTP, SFTP, and SCP sites. Using scheduled backups provides extra safety and protection against hard drive failures and data loss. 

The system backup feature saves all CounterACT device and Console settings. 

This data includes the following:
- Configuration
- License
- Operating System configuration
- Plugins/Modules

These categories include, for example:
- Forescout platform IP address
- License information
- Channel
- Email
- Internal network parameters
- Basic and advanced NAC Policy definitions
- Legitimate traffic definitions
- Report schedules'
  desc 'check', 'Check Forescout to determine if the network device is configured to conduct backups.

1. Open the Forescout Console and select Tools >> Advanced >> Backup.
2. On the “System Backup” tab, verify the "Enable System Backup" radio button is selected.
3. Verify the Backup schedule is selected to at least "weekly".

If Forescout does not support organizational requirements to conduct backups of information system documentation, including security-related documentation when changes occur or weekly, whichever is sooner, this is a finding.'
  desc 'fix', 'Configure Forescout to conduct backups.

Setup a backup server.
1. Open the Forescout Console and select Tools >> Advanced >> Backup >> Backup Server.
2. Click "SCP" or "SFTP" for the transfer protocol.
3. Add the IP address of the backup destination server.
4. Add the directory to receive the file.
5. Add PKI key (preferred) or add username and DoD compliant password for the backup account to be used.
6. Enable "Authenticate Destination Sever".
7. Test the file transfer.
8. Click "Apply".

Generate a backup job.
1. Click the System Backup tab.
2. Select "Enable System Backup".
3. Under Backup Schedule, add a "Generate backup at" and enter a time to run the backup in accordance with site procedures.
4. Select "Weekly" for Recurrence  Pattern.

When changes to the configuration occur, the admin must immediately create a new backup by clicking "Backup Now" on the Backup screen.'
  impact 0.5
  ref 'DPMS Target Forescout Network Device Management'
  tag check_id: 'C-33887r616549_chk'
  tag severity: 'medium'
  tag gid: 'V-230957'
  tag rid: 'SV-230957r616550_rule'
  tag stig_id: 'FORE-NM-000300'
  tag gtitle: 'SRG-APP-000516-NDM-000341'
  tag fix_id: 'F-33860r615878_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-000539']
  tag nist: ['CM-6 b', 'CP-9 (c)']
end
