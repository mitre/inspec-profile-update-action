control 'SV-242256' do
  title 'The TippingPoint SMS must support organizational requirements to conduct backups of information system documentation, including security-related documentation, when changes occur or weekly, whichever is sooner.'
  desc 'Information system backup is a critical step in maintaining data assurance and availability. Information system and security-related documentation contains information pertaining to system configuration and security settings. If this information were not backed up, and a system failure were to occur, the security settings would be difficult to reconfigure quickly and accurately. Maintaining a backup of information system and security-related documentation provides for a quicker recovery time when system outages occur.

This control requires the network device to support the organizational central backup process for user account information associated with the network device. This function may be provided by the network device itself; however, the preferred best practice is a centralized backup rather than each network device performing discrete backups.'
  desc 'check', 'In the SMS client, ensure backups are enabled and scheduled. 

1. Select Admin >> Database >> Backup.
2. If no scheduled backup is configured, or if the backup is not configured at least weekly then this is a finding.'
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
  tag check_id: 'C-45531r710773_chk'
  tag severity: 'medium'
  tag gid: 'V-242256'
  tag rid: 'SV-242256r710775_rule'
  tag stig_id: 'TIPP-NM-000590'
  tag gtitle: 'SRG-APP-000516-NDM-000341'
  tag fix_id: 'F-45489r710774_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-000539']
  tag nist: ['CM-6 b', 'CP-9 (c)']
end
