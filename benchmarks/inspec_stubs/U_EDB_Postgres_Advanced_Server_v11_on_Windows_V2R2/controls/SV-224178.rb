control 'SV-224178' do
  title 'The EDB Postgres Advanced Server must protect the confidentiality and integrity of all information at rest.'
  desc 'This control is intended to address the confidentiality and integrity of information at rest in non-mobile devices and covers user information and system information. Information at rest refers to the state of information when it is located on a secondary storage device (e.g., disk drive, tape drive) within an organizational information system. Applications and application users generate information throughout the course of their application use.

User data generated, as well as application-specific configuration data, must be protected. Organizations may choose to employ different mechanisms to achieve confidentiality and integrity protections, as appropriate.

If the confidentiality and integrity of application data is not protected, the data will be open to compromise and unauthorized modification.'
  desc 'check', 'If the application owner and Authorizing Official have determined that encryption of data at rest is NOT required, this is not a finding.

Right-click on <postgresql data directory>, select properties, then select the General tab and the Advanced button.

If the "Encrypt contents to secure data" check box is not checked, this is a finding.'
  desc 'fix', 'Complete these steps as the Windows user that serves as the user who is configure to run the EDB Postgres database service. If done as a different user, the Windows database service user will be unable to view this folder and therefore unable to start the database. By default, the service is configured to be run by the NetworkService account, which is a special Windows account that may not have the ability to encrypt the data directory. As a result, it may be necessary to change the service to run under a different account that can access the directory and encrypt it.

Use the following steps, to update the service, encrypt the data directory, and restart the service:
1. Change the edb-as-11 service to run as a local user account that is the same domain user that will be used to encrypt the data directory (ex. "administrator").
Open Computer Management >> Services.
Highlight the "edb-as-11 service".
Stop the service.
Select the service properties.
Select the "Log On" tab, and update the "Log on as" setting to an account such as "Administrator".

2. Encrypt the data directory by following these instructions (logged in as the user who runs the service):
Right-click on <postgresql data directory>, select properties, select the Advanced button in the General tab, and then select the "Encrypt contents to secure data" checkbox in the "Advanced Attributes" window. Select the option to apply to subfolders and files when prompted. 

3. Restart the EDB service after encrypting the drive.'
  impact 0.7
  ref 'DPMS Target EDB Postgres Advanced Server v11 on Windows'
  tag check_id: 'C-25851r495552_chk'
  tag severity: 'high'
  tag gid: 'V-224178'
  tag rid: 'SV-224178r836881_rule'
  tag stig_id: 'EP11-00-005700'
  tag gtitle: 'SRG-APP-000231-DB-000154'
  tag fix_id: 'F-25839r495553_fix'
  tag 'documentable'
  tag legacy: ['SV-109483', 'V-100379']
  tag cci: ['CCI-001199']
  tag nist: ['SC-28']
end
