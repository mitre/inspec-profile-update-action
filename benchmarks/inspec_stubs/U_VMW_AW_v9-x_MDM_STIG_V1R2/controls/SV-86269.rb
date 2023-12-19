control 'SV-86269' do
  title 'The AirWatch MDM Server must leverage the MDM Platform user accounts and groups for AirWatch MDM Server user identification and authentication and the MDM Platform accounts must be implemented via an enterprise directory service.'
  desc 'A comprehensive account management process that includes automation helps to ensure the accounts designated as requiring attention are consistently and promptly addressed. If an attacker compromises an account, the entire MDM Server infrastructure is at risk. Providing automated support functions for the management of accounts will ensure only active accounts will be granted access with the proper authorization levels. These objectives are best achieved by configuring the AirWatch MDM Server to leverage an enterprise authentication mechanism (e.g., Microsoft Active Directory Kerberos).

SFR ID: FIA'
  desc 'check', 'On the AirWatch console complete the following procedure to ensure that the AirWatch MDM Server is configured to leverage an enterprise authentication mechanism, and that AirWatch users can only use directory accounts to enroll into the AirWatch MDM Server:

1. For MDM Server Platform configuration, refer to "VMware AirWatch Directory Services Integration" guide artifact, pages 9-18.
2. Log into the AirWatch MDM Administration console.
3. Choose "Groups and Settings".
4. Choose "All Settings".
5. Under "System" heading, choose "Enterprise Integration".
6. Choose "Directory Services".
7. Under "Server" tab, verify directory service connection information.
8. Under "User" tab, verify User Group connection information.
9. Under "Group" tab, verify Group connection information.
10. Choose "X" to close screen.
11. Choose "Groups and Settings".
12. Choose "All Settings".
13. Under "Devices and Users" heading choose "General".
14. Choose "Enrollment".
15. On "Authentication Modes" setting, verify only the box titled "Directory" is selected.

If on the AirWatch MDM server console "Directory" is not selected as the authentication mode, this is a finding.'
  desc 'fix', 'Configure the AirWatch MDM Server to leverage an enterprise authentication mechanism.

On the AirWatch console complete the following procedure to leverage an enterprise authentication mechanism, and configure users to leverage directory service accounts for enrollment:

1. Follow steps on pages 9-18 of "VMware AirWatch Directory Services" guide artifact to connect AirWatch MDM Server application to enterprise authentication mechanism.
2. Log into the AirWatch MDM Administration console.
3. Choose "Groups and Settings".
4. Choose "All Settings".
5. Under "Devices and Users" heading, choose "General".
6. Choose "Enrollment".
7. On "Authentication Modes" setting, check the box labeled "Directory" and uncheck all other options.
8. Choose "Save".'
  impact 0.5
  ref 'DPMS Target AirWatch MDM 9.x'
  tag check_id: 'C-71975r2_chk'
  tag severity: 'medium'
  tag gid: 'V-71645'
  tag rid: 'SV-86269r1_rule'
  tag stig_id: 'VMAW-09-000550'
  tag gtitle: 'PP-MDM-204101 PP-MDM-204102'
  tag fix_id: 'F-77971r2_fix'
  tag 'documentable'
  tag cci: ['CCI-000015']
  tag nist: ['AC-2 (1)']
end
