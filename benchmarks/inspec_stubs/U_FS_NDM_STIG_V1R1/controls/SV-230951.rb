control 'SV-230951' do
  title 'Forescout must  enforce access restrictions associated with changes to the firmware, OS, USB port, and console port.'
  desc 'Changes to the hardware or software components of the network device can have significant effects on the overall security of the network. Therefore, only qualified and authorized individuals must be allowed administrative access to the network device for implementing any changes or upgrades. This requirement applies to updates of the application files, configuration, ACLs, and policy filters.

There is a USB port and a console RJ45 port.

The Console port is secured by the CLI security configuration.

The USB port is only accessible via the CLI, not the web manager tool. The user will be prompted to see if it should be turned on. It is off by default and requires authorized login from the CLI.'
  desc 'check', 'Check Forescout to determine if only authorized administrators have permissions for changes, deletions, and updates on the network device. Inspect the maintenance log to verify changes are being made only by the system administrators.

1. Log on to the Forescout Administrator UI with admin or operator credentials.
2. From the menu, select Tools >> Options >> CounterACT User Profiles.
3. Select (highlight) the user profile to be reviewed (group or user) and then select "Edit".
4. Verify the non-administrator account selected does not have "update" on the "Permissions" tab for "Forescout Appliance Configuration".

If unauthorized users are allowed to change the hardware or software, this is a finding.'
  desc 'fix', 'Configure Forescout to prevent access to change the software resident within software libraries for unauthorized personnel.

View each of the Forescout user group accounts associated with the external user directory groups (e.g., RADIUS, Active directory, LDAP). 

Perform the following actions for each group:
1. Log on to the Forescout Console and select Tools >> Options >> Console User Profiles.
2. Select the user group that is not authorized access according to the SSP. 
3. Select "Edit" and the "Permissions" tab.
4. Verify the options for "Module Management" or "Software Upgrade" are not selected.'
  impact 0.5
  ref 'DPMS Target Forescout Network Device Management'
  tag check_id: 'C-33881r603692_chk'
  tag severity: 'medium'
  tag gid: 'V-230951'
  tag rid: 'SV-230951r615886_rule'
  tag stig_id: 'FORE-NM-000240'
  tag gtitle: 'SRG-APP-000516-NDM-000335'
  tag fix_id: 'F-33854r603693_fix'
  tag 'documentable'
  tag cci: ['CCI-000345', 'CCI-000366']
  tag nist: ['CM-5', 'CM-6 b']
end
