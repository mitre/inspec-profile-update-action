control 'SV-93307' do
  title 'The Tanium Server must be configured with a connector to sync to Microsoft Active Directory for account management functions, must isolate security functions from non-security functions, and must terminate shared/group account credentials when members leave the group.'
  desc 'By restricting access to the Tanium Server to only Microsoft Active Directory, user accounts and related permissions can be strictly monitored. Account management will be under the operational responsibility of the System Administrator for the Windows Operation System Active Directory.

An isolation boundary provides access control and protects the integrity of the hardware, software, and firmware that perform security functions.

Security functions are the hardware, software, and/or firmware of the information system responsible for enforcing the system security policy and supporting the isolation of code and data on which the protection is based.

Developers and implementers can increase the assurance in security functions by employing well-defined security policy models; structured, disciplined, and rigorous hardware and software development techniques; and sound system/security engineering principles. Implementation may include isolation of memory space and libraries. Applications restrict access to security functions through the use of access control mechanisms and by implementing least privilege capabilities.

If shared/group account credentials are not terminated when individuals leave the group, the user who left the group can still gain access even though they are no longer authorized. A shared/group account credential is a shared form of authentication that allows multiple individuals to access the application using a single account. There may also be instances when specific user actions need to be performed on the information system without unique user identification or authentication. Examples of credentials include passwords and group membership certificates.

'
  desc 'check', 'Access the Tanium Module server interactively.

Log on with an account with administrative privileges to the server.

Click "Start".

Click the down arrow to view Apps.

Find "Tanium Connection Manager AD Sync".

Right-click on the icon.

Choose to Run-as administrator, at the "User Account Control" window prompt.

Click "Yes".

In the "Tanium Connection Manager" configuration window, select the "Connector Plug-Ins" tab.

Verify a plug-in exists for the "Type" of "Active Directory Sync".

If no plug-in exists with the "Type" of "Active Directory Sync", this is a finding.'
  desc 'fix', %q(Access the Tanium Module server interactively.

Log on with an account with administrative privileges to the server.

Click "Start" and click the down arrow to view Apps.

Find "Tanium Connection Manager AD Sync".

Right-click on the icon.

Choose to Run-as administrator, at the "User Account Control window" prompt.

Click "Yes".

In the Tanium Connection Manager configuration window, select the "Connector Plug-Ins" tab.

Click the "+" (plus sign) to add a connector.

For "Connector Type:" select "Active Directory Sync" from the drop-down menu.

Assign a unique "Connector Name:" or leave the default of "Active Directory Sync".

Click "OK".

Configure "Active Directory" and "Configuration" tabs with variables according to the site's Active Directory configuration. 

Consult the Tanium Administrator for these variables.)
  impact 0.5
  ref 'DPMS Target Tanium 7.0'
  tag check_id: 'C-78171r1_chk'
  tag severity: 'medium'
  tag gid: 'V-78601'
  tag rid: 'SV-93307r1_rule'
  tag stig_id: 'TANS-CN-000002'
  tag gtitle: 'SRG-APP-000023'
  tag fix_id: 'F-85337r1_fix'
  tag satisfies: ['SRG-APP-000023', 'SRG-APP-000233', 'SRG-APP-000317']
  tag 'documentable'
  tag cci: ['CCI-000015', 'CCI-001084', 'CCI-002142']
  tag nist: ['AC-2 (1)', 'SC-3', 'AC-2 (10)']
end
