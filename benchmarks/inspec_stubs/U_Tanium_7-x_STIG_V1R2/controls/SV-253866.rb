control 'SV-253866' do
  title 'The Tanium Threat Response Local Directory Source must be configured to restrict access to only authorized maintainers of threat intel.'
  desc 'Using trusted and recognized indicator of compromise (IOC) sources may detect and prevent systems from becoming compromised. An IOC stream is a series or stream of intel that is imported from a vendor based on a subscription service or manually downloaded and placed in a folder. Threat Response can be configured to retrieve the IOC content on a regularly scheduled basis. The items in an IOC stream can be manipulated separately after they are imported.'
  desc 'check', 'Consult with the Tanium system administrator to determine if the Tanium Threat Response module is being used. If it is not, his finding is not applicable.

If the Local Directory Source type is being used, determine where they get their IOC stream.

1. Access the Tanium Module Server interactively.

2. Log on to the server with an account that has administrative privileges.

3. Open an Explorer window.

4. Navigate to Program Files >> Tanium >> Tanium Module Server >> services >> threat-response-files.

5. Right-click the folder and choose "Properties".

6. Select the "Security" tab.

7. Click the "Advanced" button.

If the accounts listed in the "Security" tab do not match the list of accounts in the Tanium documentation, this is a finding.'
  desc 'fix', '1. Access the Tanium Module Server interactively.

2. Log on to the server with an account that has administrative privileges.

3. Open an Explorer window.

4. Navigate to Program Files >> Tanium >> Tanium Module Server >> services >> threat-response-files.

5. Right-click the folder and choose "Properties".

6. Select the "Security" tab.

7. Click the "Advanced" button.

If the accounts listed in the "Security" tab do not match the list of accounts, with the exception of SYSTEM, remove the additionally listed accounts.

If the accounts listed in the "Security" tab are missing accounts from the documentation, with the exception of SYSTEM, add the additionally listed accounts with a minimum of READ permission.'
  impact 0.5
  ref 'DPMS Target Tanium 7.x'
  tag check_id: 'C-57318r842624_chk'
  tag severity: 'medium'
  tag gid: 'V-253866'
  tag rid: 'SV-253866r842626_rule'
  tag stig_id: 'TANS-SV-000049'
  tag gtitle: 'SRG-APP-000039'
  tag fix_id: 'F-57269r842625_fix'
  tag 'documentable'
  tag cci: ['CCI-001414']
  tag nist: ['AC-4']
end
