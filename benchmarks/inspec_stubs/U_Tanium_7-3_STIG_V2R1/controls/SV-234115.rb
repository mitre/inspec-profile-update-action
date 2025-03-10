control 'SV-234115' do
  title 'The Tanium Detect Local Directory Source must be configured to restrict access to only authorized maintainers of Intel.'
  desc 'An IOC stream is a series or ""stream"" of intel that are imported from a vendor based on a subscription service or manually downloaded and placed in a folder. Detect can be configured to retrieve the IOC content on a regularly scheduled basis. The items in an IOC stream can be separately manipulated after they are imported.'
  desc 'check', 'Consult with the Tanium System Administrator to determine if the Tanium Detect module is being used, if not then this finding is Not Applicable.

If being used then determine where they get their IOC Stream.

Access the Tanium Module Server interactively.

Log on to the server with an account that has administrative privileges.

Open an Explorer window.

Navigate to Program Files >> Tanium >> Tanium Module Server >> services >> detect3-files

Right-click on the folder and choose "Properties".

Select the "Security" tab.

Click on the "Advanced" button.

If the accounts listed in the "Security" tab do not match the list of accounts found in the Tanium documentation, this is a finding.'
  desc 'fix', 'Consult with the Tanium System Administrator to determine if the "Detect" module is being used, if not then this is Not Applicable.

Access the Tanium Module Server interactively.

Log on to their server with an account that has administrative privileges.

Open an Explorer window.

Navigate to Program Files >> Tanium >> Tanium Module Server >> services >> detect3-files

Right-click on the folder and choose "Properties".

Select the "Security" tab.

Click on the "Advanced" button.

If the accounts listed in the "Security" tab do not match the list of accounts, with the exception of SYSTEM, remove the additionally listed accounts.

If the accounts listed in the "Security" tab are missing accounts from the documentation, with the exception of SYSTEM, add the additionally listed accounts with a minimum of READ permissions.'
  impact 0.5
  ref 'DPMS Target Tanium 7.3'
  tag check_id: 'C-37300r610845_chk'
  tag severity: 'medium'
  tag gid: 'V-234115'
  tag rid: 'SV-234115r612749_rule'
  tag stig_id: 'TANS-SV-000049'
  tag gtitle: 'SRG-APP-000039'
  tag fix_id: 'F-37265r610846_fix'
  tag 'documentable'
  tag legacy: ['SV-102303', 'V-92201']
  tag cci: ['CCI-001414']
  tag nist: ['AC-4']
end
