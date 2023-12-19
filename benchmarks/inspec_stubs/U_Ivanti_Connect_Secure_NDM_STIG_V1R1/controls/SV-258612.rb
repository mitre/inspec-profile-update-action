control 'SV-258612' do
  title 'The ICS must be configured to support organizational requirements to conduct weekly backups of information system documentation, including security-related documentation.'
  desc 'Information system backup is a critical step in maintaining data assurance and availability. Information system and security-related documentation contains information pertaining to system configuration and security settings. If this information were not backed up, and a system failure were to occur, the security settings would be difficult to reconfigure quickly and accurately. Maintaining a backup of information system and security-related documentation provides for a quicker recovery time when system outages occur.

This control requires the network device to support the organizational central backup process for user account information associated with the network device. This function may be provided by the network device itself; however, the preferred best practice is a centralized backup rather than each network device performing discrete backups.'
  desc 'check', 'In the ICS Web UI, navigate to Maintenance >> Archiving >> Archive Servers.
1. Under "Archive Settings" verify an archive server is configured.
2. Under "Archive Schedule" verify "Archive System Configuration", and "Archive User Accounts" are selected.
3. Under "Archive Schedule" verify "Archive System Configuration", and "Archive User Accounts" are configured at a specific time and day of the week.
4. Under "Archive Schedule", if "Archive System Configuration", and "Archive User Accounts" are configured with a password for backup encryption.

If the ICS does not support organizational requirements to conduct backups of information system documentation, including security-related documentation weekly, this is a finding.'
  desc 'fix', 'In the ICS Web UI, navigate to Maintenance >> Archiving >> Archive Servers.
1. Click "SCP" if using an SFTP/SCP server; other mechanisms may not be allowed due to local security policy. NOTE: Check with the ISSM before configuring anything other than SCP.
2. Under "Archive Server" type the hostname or IPv4/IPv6 address.
3. In "Destination Directory" type the path of the backup (e.g., "/backupfolder/ics/").
4. In the "Username" field, type the username with SCP/SFTP permissions on the backup server.
5. In the "Password" field, type the password.
6. Under "Archive Schedule", select "Archive System Configuration", then click the day of the week and time when the backup should be sent.
7. Under "Archive System Configuration", ensure a password is given to encrypt the backup.
8. Under "Archive Schedule", select "Archive User Accounts", then click the day of the week and time when the backup should be sent.
9. Under "Archive User Accounts", ensure a password is given to encrypt the backup.
10. Click "Save Changes".'
  impact 0.5
  ref 'DPMS Target Ivanti Connect Secure NDM'
  tag check_id: 'C-62352r930522_chk'
  tag severity: 'medium'
  tag gid: 'V-258612'
  tag rid: 'SV-258612r930524_rule'
  tag stig_id: 'IVCS-NM-000380'
  tag gtitle: 'SRG-APP-000516-NDM-000341'
  tag fix_id: 'F-62261r930523_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-000539']
  tag nist: ['CM-6 b', 'CP-9 (c)']
end
