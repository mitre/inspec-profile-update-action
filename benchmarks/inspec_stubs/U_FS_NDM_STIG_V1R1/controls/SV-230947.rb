control 'SV-230947' do
  title 'Forescout must enforce access restrictions associated with changes to device configuration.'
  desc 'Failure to provide logical access restrictions associated with changes to device configuration may have significant effects on the overall security of the system. 

For Forescout, ensure only authorized users have access to user profile permissions. All other admins are blocked from access via the console tools and/or web portal based on permissions set on the Edit user profile.'
  desc 'check', 'Determine if the network device enforces access restrictions associated with changes to device configuration.

1. Log on to the Forescout Administrator UI with admin or operator credentials.
2. From the menu, select Tools >> Options >> User Console and Options.
3. Select (highlight) the user profile to be reviewed (group or user) and then select Edit >> Permissions.
4. Check user against the current SSP and ensure only the users that should have the privilege to make changes have the CounterACT Appliance Configuration; CounterACT Appliance Control; Module Control; Multiple CounterACT Appliance Management; Policy Control; Policy Management; and User Management privileges selected.

If the network device does not enforce such access restrictions, this is a finding.'
  desc 'fix', 'Remove accounts that are not authorized. Do not remove the account of last resort.

1. Log on to the Forescout Administrator UI with admin or operator credentials.
2. From the menu, select Tools >> Options >> User Console and Options.
3. Select (highlight) the user profile to be reviewed (group or user) and then select Edit >> Permissions.
4. Check user against current SSP and ensure only the users that should have privilege to make changes have the CounterACT Appliance Configuration; CounterACT Appliance Control; Module Control; Multiple CounterACT Appliance Management; Policy Control; Policy Management; and User Management privileges selected.
5. Delete or disable unauthorized users.'
  impact 0.5
  ref 'DPMS Target Forescout Network Device Management'
  tag check_id: 'C-33877r603680_chk'
  tag severity: 'medium'
  tag gid: 'V-230947'
  tag rid: 'SV-230947r615886_rule'
  tag stig_id: 'FORE-NM-000200'
  tag gtitle: 'SRG-APP-000380-NDM-000304'
  tag fix_id: 'F-33850r603681_fix'
  tag 'documentable'
  tag cci: ['CCI-001813']
  tag nist: ['CM-5 (1) (a)']
end
