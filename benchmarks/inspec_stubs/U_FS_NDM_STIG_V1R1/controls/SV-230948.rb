control 'SV-230948' do
  title 'Forescout must audit the enforcement actions used to restrict access associated with changes to the device.'
  desc 'Without auditing the enforcement of access restrictions against changes to the device configuration, it will be difficult to identify attempted attacks, and an audit trail will not be available for forensic investigation for after-the-fact actions. 

Forescout must only be configures such that only authorized users have access to user profile permissions. All other admins are blocked from access via the console tools and/or web portal based on permissions set on the Edit user profile.'
  desc 'check', 'Determine if the network device audits the enforcement actions used to restrict access associated with changes to the device. This requirement may be verified by demonstration, configuration review, or validated test results.

1. Log on to the Forescout Administrator UI with admin or operator credentials.
2. From the menu, select Tools >> Options >> User Console and Options.
3. Select (highlight) the user profile to be reviewed (group or user) and then select Edit >> Permissions.
4. Check user against current SSP and ensure only the users with privileges to make changes have the Least Privilege required permissions.

If the network device does not audit the enforcement actions used to restrict access associated with changes to the device, this is a finding.'
  desc 'fix', 'Remove accounts that are not authorized. Do not remove the account of last resort. Ensure a Least Privilege Permission approach is taken with all accounts created.

1. Log on to the Forescout Administrator UI with admin or operator credentials.
2. From the menu, select Tools >> Options >> User Console and Options.
3. Select (highlight) the user profile to be reviewed (group or user) and then select Edit >> Permissions.
4. Check user against current SSP and ensure only the users that are allowed privileges to make changes have the Least Privilege required permissions.
5. Delete or disable unauthorized users.'
  impact 0.3
  ref 'DPMS Target Forescout Network Device Management'
  tag check_id: 'C-33878r603683_chk'
  tag severity: 'low'
  tag gid: 'V-230948'
  tag rid: 'SV-230948r615886_rule'
  tag stig_id: 'FORE-NM-000210'
  tag gtitle: 'SRG-APP-000381-NDM-000305'
  tag fix_id: 'F-33851r603684_fix'
  tag 'documentable'
  tag cci: ['CCI-001814']
  tag nist: ['CM-5 (1)']
end
