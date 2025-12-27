control 'SV-254890' do
  title 'The Tanium Threat Response Local Directory Source must be configured to restrict access to only authorized maintainers of Threat Intel.'
  desc 'Using trusted and recognized IOC sources may detect and prevent systems from becoming compromised. An IOC stream is a series or stream of intel imported from a vendor based on a subscription service or manually downloaded and placed in a folder. Threat Response can be configured to retrieve the IOC content on a regularly scheduled basis. The items in an IOC stream can be separately manipulated after they are imported.'
  desc 'check', 'Consult with the Tanium System Administrator to determine if the Tanium Threat Response module is being used. If not, this finding is Not Applicable.

If the Local Directory Source type is being used, then determine where they get their IOC Stream.

1. Access the Tanium Module Server interactively.

2. Log on to the server with an account that has administrative privileges.

3. Open an Explorer window.

4. Navigate to Program Files >> Tanium >> Tanium Module Server >> Services >> Threat-Response-Files.

5. Right-click on the folder and choose "Properties".

6. Select the "Security" tab.

7. Click "Advanced".

If the accounts listed in the Security tab do not match the list of accounts found in the Tanium documentation, this is a finding.'
  desc 'fix', '1. Access the Tanium Module Server interactively.

2. Log on to the server with an account that has administrative privileges.

3. Open an Explorer window.

4. Navigate to Program Files >> Tanium >> Tanium Module Server >> Services >> Threat-Response-Files.

5. Right-click on the folder and choose "Properties".

6. Select the "Security" tab.

7. Click "Advanced".

If the accounts listed in the Security tab do not match the list of accounts, with the exception of SYSTEM, remove the additionally listed accounts.

If the accounts listed in the "Security" tab are missing accounts from the documentation, with the exception of SYSTEM, add the additionally listed accounts with a minimum of READ permissions.'
  impact 0.5
  ref 'DPMS Target Tanium 7.x Application on TanOS'
  tag check_id: 'C-58503r867568_chk'
  tag severity: 'medium'
  tag gid: 'V-254890'
  tag rid: 'SV-254890r867570_rule'
  tag stig_id: 'TANS-AP-000145'
  tag gtitle: 'SRG-APP-000039'
  tag fix_id: 'F-58447r867569_fix'
  tag 'documentable'
  tag cci: ['CCI-001414']
  tag nist: ['AC-4']
end
