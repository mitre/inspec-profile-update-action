control 'SV-83817' do
  title 'The NSX Manager must support organizational requirements to conduct backups of system-level information contained in the information system when changes occur or weekly, whichever is sooner.'
  desc 'System-level information includes default and customized settings and security attributes, including ACLs that relate to the network device configuration, as well as software required for the execution and operation of the device. Information system backup is a critical step in ensuring system integrity and availability. If the system fails and there is no backup of the system-level information, a denial of service condition is possible for all who utilize this critical network component.
 
This control requires the network device to support the organizational central backup process for system-level information associated with the network device. This function may be provided by the network device itself; however, the preferred best practice is a centralized backup rather than each network device performing discrete backups.'
  desc 'check', 'Verify NSX Manager backups are being sent to a centralized location and when changes occur or weekly, whichever is sooner. 

Log on to NSX Manager with credentials authorized for administration, navigate and select Backup and Restore >> Backup History.

Confirm there are current backups and information is being backed up at a consistent interval.
 
If backups are not being sent to a centralized location when changes occur or weekly, whichever is sooner, this is a finding.'
  desc 'fix', 'Change NSX Manager backup configurations to send backups to a centralized location and when changes occur or weekly, whichever is sooner. 

Log on to NSX Manager with credentials authorized for administration, navigate and select "Backup and Restore".

To specify the backup location, click "Change" next to FTP Server Settings.

Type the IP address or host name of the backup system.

From the Transfer Protocol drop-down menu, select either "SFTP" or "FTP", based on what the destination supports.

Edit the default port if required.

Type the username and password required to log on to the backup system.

In the Backup Directory field, type the absolute path where backups will be stored.

Type a text string in Filename Prefix. (This text is prepended to each backup filename for easy recognition on the backup system. For example, if you type "ppdb", the resulting backup is named as ppdbHH_MM_SS_DayDDMonYYYY.)

Type the passphrase to secure the backup. (You will need this passphrase to restore the backup.)

Click "OK".

For an on-demand backup, click "Backup".

For scheduled backups, click "Change" next to "Scheduling" (frequency must be when changes occur or weekly, whichever is sooner).

From the "Backup Frequency" drop-down menu, select "Hourly", "Daily", or "Weekly". The Day of Week, Hour of Day, and Minute drop-down menus are disabled based on the selected frequency. For example, if you select Daily, the Day of Week drop-down menu is disabled as this field is not applicable to a daily frequency.

For a weekly backup, select the day of the week the data must be backed up.

For a weekly or daily backup, select the hour at which the backup must begin.

Select the minute to begin and click "Schedule". (Do not exclude logs and flow data from being backed up.)

Click "OK".'
  impact 0.3
  ref 'DPMS Target VMware NSX 6 NDM'
  tag check_id: 'C-69653r1_chk'
  tag severity: 'low'
  tag gid: 'V-69213'
  tag rid: 'SV-83817r1_rule'
  tag stig_id: 'VNSX-ND-000138'
  tag gtitle: 'SRG-APP-000516-NDM-000340'
  tag fix_id: 'F-75399r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-000537']
  tag nist: ['CM-6 b', 'CP-9 (b)']
end
