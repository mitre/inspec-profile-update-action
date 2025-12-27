control 'SV-83777' do
  title 'The NSX Manager must back up audit records at least every seven days onto a different system or system component than the system or component being audited.'
  desc 'Protection of log data includes verifying log data is not accidentally lost or deleted. Regularly backing up audit records to a different system or onto separate media than the system being audited helps to verify, in the event of a catastrophic system failure, the audit records will be retained. 
 
This helps to verify a compromise of the information system being audited does not also result in a compromise of the audit records.'
  desc 'check', 'Verify NSX Manager backups are being sent to a centralized location and when changes occur or weekly, whichever is sooner. 

Log on to NSX Manager with credentials authorized for administration, navigate and select Backup and Restore >> Backup History. 

Confirm there are current backups and records are being backed up at a consistent interval.
 
If backups are not being sent to a centralized location when changes occur or weekly, whichever is sooner, this is a finding.'
  desc 'fix', 'Change NSX Manager backup configurations to send backups to a centralized location and when changes occur or weekly, whichever is sooner.  

Log on to NSX Manager with credentials authorized for administration, navigate and select "Backup and Restore".

To specify the backup location, click "Change" next to "FTP Server Settings".

Type the IP address or host name of the backup system.

From the Transfer Protocol drop-down menu, select either "SFTP" or "FTP", based on what the destination supports.

Edit the default port if required.

Type the username and password required to log on to the backup system.

In the Backup Directory field, type the absolute path where backups will be stored.

Type a text string in Filename Prefix. (This text is prepended to each backup filename for easy recognition on the backup system. For example, if you type "ppdb", the resulting backup is named as ppdbHH_MM_SS_DayDDMonYYYY.)
Type the passphrase to secure the backup. You will need this passphrase to restore the backup.

Click "OK".

For an on-demand backup, click "Backup".

For scheduled backups, click "Change" next to Scheduling (frequency must be when changes occur or weekly, whichever is sooner).

From the Backup Frequency drop-down menu, select "Hourly", "Daily", or "Weekly". The Day of Week, Hour of Day, and Minute drop-down menus are disabled based on the selected frequency. For example, if you select "Daily", the Day of Week drop-down menu is disabled as this field is not applicable to a daily frequency.

For a weekly backup, select the day of the week the data must be backed up.

For a weekly or daily backup, select the hour at which the backup must begin.

Select the minute to begin and click "Schedule". (Do not exclude logs and flow data from being backed up.)

Click "OK."'
  impact 0.3
  ref 'DPMS Target VMware NSX 6 NDM'
  tag check_id: 'C-69613r1_chk'
  tag severity: 'low'
  tag gid: 'V-69173'
  tag rid: 'SV-83777r1_rule'
  tag stig_id: 'VNSX-ND-000043'
  tag gtitle: 'SRG-APP-000125-NDM-000241'
  tag fix_id: 'F-75359r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001348']
  tag nist: ['AU-9 (2)']
end
