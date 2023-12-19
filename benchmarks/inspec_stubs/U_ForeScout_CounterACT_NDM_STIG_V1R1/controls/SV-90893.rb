control 'SV-90893' do
  title 'CounterACT must enforce access restrictions associated with changes to the system components.'
  desc 'Changes to the hardware or software components of the network device can have significant effects on the overall security of the network. Therefore, only qualified and authorized individuals should be allowed administrative access to the network device for implementing any changes or upgrades. This requirement applies to updates of the application files, configuration, ACLs, and policy filters.'
  desc 'check', 'Check CounterACT to determine if only authorized administrators have permissions for changes, deletions, and updates on the network device. Inspect the maintenance log to verify changes are being made only by the system administrators.

1. Log on to the CounterACT Administrator UI with admin or operator credentials.
2. From the menu, select Tools >> Options >> User Console and Options.
3. Select (highlight) the user profile to be reviewed (group or user) and then select "Edit".
4. Verify the non-administrator account selected does not have "update" on the "Permissions" tab for "CounterACT Appliance Configuration".

If unauthorized users are allowed to change the hardware or software, this is a finding.'
  desc 'fix', 'Configure CounterACT to enforce access restrictions associated with changes to the system components.

1. Log on to the CounterACT Administrator UI with admin or operator credentials.
2. From the menu, select Tools >> Options >> User Console and Options.
3. Select (highlight) the user profile to be reviewed (group or user) and then select "Edit".
4. Verify the non-administrator account selected does not have "update" on the "Permissions" tab for "CounterACT Appliance Configuration".'
  impact 0.5
  ref 'DPMS Target ForeScout CounterACT NDM'
  tag check_id: 'C-75891r1_chk'
  tag severity: 'medium'
  tag gid: 'V-76205'
  tag rid: 'SV-90893r1_rule'
  tag stig_id: 'CACT-NM-000011'
  tag gtitle: 'SRG-APP-000516-NDM-000335'
  tag fix_id: 'F-82843r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000345', 'CCI-000366']
  tag nist: ['CM-5', 'CM-6 b']
end
