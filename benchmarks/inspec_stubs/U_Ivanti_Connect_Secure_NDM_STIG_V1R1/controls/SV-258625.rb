control 'SV-258625' do
  title 'The ICS must be configured to conduct backups of system level information contained in the information system when changes occur.'
  desc 'System-level information includes default and customized settings and security attributes, including ACLs that relate to the network device configuration, as well as software required for the execution and operation of the device. Information system backup is a critical step in ensuring system integrity and availability. If the system fails and there is no backup of the system-level information, a denial of service condition is possible for all who utilize this critical network component.

This control requires the network device to support the organizational central backup process for system-level information associated with the network device. This function may be provided by the network device itself; however, the preferred best practice is a centralized backup rather than each network device performing discrete backups.'
  desc 'check', 'In the ICS Web UI, navigate to Maintenance >> Archiving >> Archive Servers.

Under "Archive Settings", if there is no archive server configured, this is a finding.

Under "Archive Schedule", if "Archive System Configuration", and "Archive User Accounts" are not selected, this is a finding.

Under "Archive Schedule", if "Archive System Configuration", and "Archive User Accounts" are not configured at a specific time and day of the week, this is a finding.

Under "Archive Schedule", if "Archive System Configuration", and "Archive User Accounts" are not configured with a password for backup encryption, this is a finding.'
  desc 'fix', 'In the ICS Web UI, navigate to Maintenance >> Archiving >> Archive Servers.
1. Click "SCP" if using an SFTP/SCP server, other mechanisms may not be allowed due to local security policy. Check with the ISSM before configuring anything other than SCP.
2. Under "Archive Server", type the hostname or IPv4/IPv6 address.
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
  tag check_id: 'C-62365r930561_chk'
  tag severity: 'medium'
  tag gid: 'V-258625'
  tag rid: 'SV-258625r930563_rule'
  tag stig_id: 'IVCS-NM-000740'
  tag gtitle: 'SRG-APP-000516-NDM-000340'
  tag fix_id: 'F-62274r930562_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-000537']
  tag nist: ['CM-6 b', 'CP-9 (b)']
end
