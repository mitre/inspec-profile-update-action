control 'SV-93439' do
  title 'The Tanium IOC Detect Folder streams must be configured to restrict access to only authorized maintainers of IOCs.'
  desc 'An IOC stream is a series or "stream" of IOCs that are imported from a vendor based on a subscription service or manually downloaded and placed in a folder. IOC Detect can be configured to retrieve the IOC content on a regularly scheduled basis. The items in an IOC stream can be separately manipulated after they are imported.'
  desc 'check', 'Consult with the Tanium System Administrator to determine if the Tanium Detect module is being used. If it is not, this finding is "Not Applicable".

If it is being used, determine where the IOC stream comes from.

Access the Tanium Module Server interactively.

Log on with an account with administrative privileges to the server.

Open an Explorer window.

If the folder hosting the IOC Detect Folder streams is not mapped to the Tanium Module Server, temporarily map it to the Tanium Module Server.

Right-click on the folder and choose "Properties".

Select the "Security" tab.

Click on the "Advanced" button.

If the accounts listed in the "Security" tab do not match the list of accounts found in the Tanium documentation, this is a finding.

If the folder was temporarily mapped to the Tanium Module Server, remove the folder mapping.'
  desc 'fix', 'Consult with the Tanium System Administrator to determine if the "Detect" module is being used. If it is not, this is "Not Applicable".

Access the Tanium Module Server interactively.

Log on with an account with administrative privileges to the server.

Open an Explorer window.

If the folder hosting the IOC Detect Folder streams is not mapped to the Tanium Module Server, temporarily map it to the Tanium Module Server.

Right-click on the folder and choose "Properties".

Select the "Security" tab.

Click on the "Advanced" button.

If the accounts listed in the "Security" tab do not match the list of accounts, with the exception of SYSTEM, remove the additionally listed accounts.

If the accounts listed in the "Security" tab are missing accounts from the documentation, with the exception of SYSTEM, add the additionally listed accounts with a minimum of READ permissions.

If the folder was temporarily mapped to the Tanium Module Server, remove the folder mapping.'
  impact 0.5
  ref 'DPMS Target Tanium 7.0'
  tag check_id: 'C-78309r1_chk'
  tag severity: 'medium'
  tag gid: 'V-78733'
  tag rid: 'SV-93439r1_rule'
  tag stig_id: 'TANS-SV-000049'
  tag gtitle: 'SRG-APP-000039'
  tag fix_id: 'F-85475r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001414']
  tag nist: ['AC-4']
end
