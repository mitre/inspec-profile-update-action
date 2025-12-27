control 'SV-81487' do
  title 'The Tanium Application Server must be configured with a connector to sync to Microsoft Active Directory for account management functions.'
  desc 'By restricting access to the Tanium Server to only Microsoft Active Directory, user accounts and related permissions can be strictly monitored. Account management will be under the operational responsibility of the System Administrator for the Windows Operation System Active Directory.'
  desc 'check', 'Access the Tanium Module server interactively and log on as an Administrator.

Click “Start” and click the down arrow to view Apps. 

Find "Tanium Connection Manager", right-click on the icon and choose to Run-as administrator and confirm at the User Account Control window prompt.

In the "Tanium Connection Manager" configuration window, select the "Connector Plug-Ins" tab. 

Verify a plug-in exists for the "Type of Active Directory Sync".

If no plug-in exists with the "Type of Active Directory Sync", this is a finding.'
  desc 'fix', %q(Access the Tanium Module server interactively and log on as an Administrator.

Click “Start” and click the down arrow to view Apps. 

Find Tanium Connection Manager, right-click on the icon and choose to Run-as administrator and confirm.

In the Tanium Connection Manager configuration window, select the "Connector Plug-Ins" tab.

Click the + to add a connector

For Connector Type:, choose Active Directory Sync

Assign a unique Connector Name:

Click “OK”.

Configure Active Directory and configuration tabs with variables according to site's Active Directory configuration.)
  impact 0.5
  ref 'DPMS Target Tanium 6.5'
  tag check_id: 'C-67633r1_chk'
  tag severity: 'medium'
  tag gid: 'V-66997'
  tag rid: 'SV-81487r1_rule'
  tag stig_id: 'TANS-CN-000002'
  tag gtitle: 'SRG-APP-000023'
  tag fix_id: 'F-73097r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000015']
  tag nist: ['AC-2 (1)']
end
