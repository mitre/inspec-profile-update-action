control 'SV-60211' do
  title 'The AirWatch MDM Server must uniquely identify mobile devices managed by the server prior to connecting to the device.'
  desc 'When managed mobile devices connect to the AirWatch MDM Server, the security policy and possible sensitive DoD data will be pushed to the device.  In addition, the device may be provided access to application and web servers on the DoD network.  Therefore, strong authentication of the user on the device is required to ensure sensitive DoD data is not exposed and unauthorized access to the DoD network is not granted, exposing the network to malware and attack.'
  desc 'check', 'Review the AirWatch MDM Server configuration to ensure the AirWatch MDM Server can uniquely identify mobile devices managed by the server prior to connecting to the device. If this function is not present, this is a finding.

The AirWatch system meets this requirement both by inherent certificate technology, and also user authentication via integration with a STIG compliant Active Directory system upon device "Enrollment" (initial entry into DoD MDM system which initiates provisioning and access):

AirWatch, upon native installation, activates a "Secure Channel" and generates root X.509 certificate to identify itself to devices and issue public keys to those devices for authentication. To verify that Secure Channel is active: (1) click "Menu" from top tool bar, (2) click "System Configuration" under "Configuration" heading, (3) click "System" on left-hand tool bar, (4) click "Advanced", and (5) click "Secure Channel Certificate". (6) Ensure Secure Channel is enabled for applicable platforms and certificate is uploaded.

User utilizes User ID/Password combination via Active Directory to connect device to AirWatch system: (1) click "Menu" from top tool bar, (2) click "System Configuration" under "Configuration" heading, (3) click "System" on left-hand tool bar, (4) click "Enterprise Integration", and (5) click "Directory Services". (6) On "Server" tab, verify URL for Active Directory server, applicable encryption method and port, authentication type, and service account details (service account for AirWatch must be created with Read permissions to Active Directory). On "User" and "Group" tabs (6) verify applicable Domain and Base Domain Names are entered.

To verify specific Active Directory User Accounts: (1) click "Menu" on top tool bar, (2) click "Users" under "Accounts" heading, (4) click applicable user, and check the account is set for "Directory" authentication.

To verify device Enrollment (connection to AirWatch MDM Server from device) via Active Directory authentication is configured: (1) click "Menu" from top tool bar, (2) click "System Configuration" under "Configuration" heading, (3) click "Devices and Users" on left-hand tool bar, (4) click "General", and (5) click "Enrollment". (6) Under Authentication tab, ensure box labeled "Directory" in Authentication Modes section is checked.'
  desc 'fix', 'Configure the AirWatch MDM Server to authenticate through the Enterprise Authentication Mechanism.

To install AirWatch Secure Channel, please refer to the "Directory Services Guide" page 4 for information on integrating Active Directory servers with the AirWatch system, and page 8 for information on creating AirWatch users utilizing Active Directory sync for installation instructions on host server and network. Typically installed during initial AirWatch installation.

To enforce User ID/Password combination via Active Directory to connect device to AirWatch system: (1) click "Menu" from top tool bar, (2) click "System Configuration" under "Configuration" heading, (3) click "System" on left-hand tool bar, (4) click "Enterprise Integration", and (4) click "Directory Services". (5) On "Server" tab, enter URL for Active Directory server, applicable encryption method and port, authentication type, and service account details (service account for AirWatch must be created with Read permissions to Active Directory; see "Enrollment Overview Guide" page 7 for "Enabling Directory Service-Based Enrollment" and "Agent Security" page 2 for certificate authentication information for further information). On "User" and "Group" tabs (6) select applicable Domain and Base Domain Names. (7) Click "Save".

To create Active Directory User Account: (1) click "Menu" on top tool bar, (2) click "Users" under "Accounts" heading, and (3) click "Add". (4) Select "Directory" as authentication type, and (5) enter user name, then, (6) click "Search User". (7) Click "Save" to add user account.

To enable device Enrollment (connection to AirWatch MDM Server from device) via Active Directory authentication: (1) click "Menu" from top tool bar, (2) click "System Configuration" under "Configuration" heading, (3) click "Devices and Users" on left-hand tool bar, (4) click "General", and (5) click "Enrollment". (6) Under Authentication tab, check box labeled "Directory" in Authentication Modes section. (7) Click "Save".'
  impact 0.5
  ref 'DPMS Target AirWatch MDM 6.5'
  tag check_id: 'C-50105r2_chk'
  tag severity: 'medium'
  tag gid: 'V-47339'
  tag rid: 'SV-60211r1_rule'
  tag stig_id: 'ARWA-02-000195'
  tag gtitle: 'SRG-APP-158-MDM-153-MDM'
  tag fix_id: 'F-51045r2_fix'
  tag 'documentable'
  tag cci: ['CCI-000778']
  tag nist: ['IA-3']
end
