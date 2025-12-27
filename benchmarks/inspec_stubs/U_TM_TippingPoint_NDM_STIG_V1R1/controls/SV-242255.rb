control 'SV-242255' do
  title 'The TippingPoint SMS must be configured to conduct backups of system level information contained in the information system when changes occur.'
  desc 'System-level information includes default and customized settings and security attributes, including ACLs that relate to the network device configuration, as well as software required for the execution and operation of the device. Information system backup is a critical step in ensuring system integrity and availability. If the system fails and there is no backup of the system-level information, a denial of service condition is possible for all who utilize this critical network component.

This control requires the network device to support the organizational central backup process for system-level information associated with the network device. This function may be provided by the network device itself; however, the preferred best practice is a centralized backup rather than each network device performing discrete backups.'
  desc 'check', 'In the SMS client, ensure backups are enabled and scheduled.

1. Select Admin >> Database >> Backup.
2. If no scheduled backup is configured, or if the backup is not configured at least weekly, this is a finding.'
  desc 'fix', 'In the SMS client, ensure backups are enabled and scheduled. 

1. Select Admin >> Database >> Backup.
2. Select New.
3. Enter a name, weekly, the date and time to backup, and no end date.
4. Include the most recent TOS and DV, include the certificate and keys, and then encrypt the backup. Provide a password.
5. Click Next.
6. Select SFTP.
7. Enter the SFTP URL, path, and location, username, and password in the following example format:  "192.168.1.1:/home/sms/backup.bak".
8. Select Next >> Finish.'
  impact 0.5
  ref 'DPMS Target Trend Micro TippingPoint NDM'
  tag check_id: 'C-45530r710770_chk'
  tag severity: 'medium'
  tag gid: 'V-242255'
  tag rid: 'SV-242255r710772_rule'
  tag stig_id: 'TIPP-NM-000580'
  tag gtitle: 'SRG-APP-000516-NDM-000340'
  tag fix_id: 'F-45488r710771_fix'
  tag 'documentable'
  tag cci: ['CCI-000537', 'CCI-000366']
  tag nist: ['CP-9 (b)', 'CM-6 b']
end
