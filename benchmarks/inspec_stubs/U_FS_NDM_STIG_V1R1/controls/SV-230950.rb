control 'SV-230950' do
  title 'Forescout must limit privileges to change the modules and OSs resident within software libraries.'
  desc 'Changes to any software components of the network device can have significant effects on the overall security of the network. Therefore, only qualified and authorized individuals must be allowed administrative access to the network device for implementing any changes or upgrades. If the network device were to enable non-authorized users to make changes to software libraries, those changes could be implemented without undergoing testing, validation, and approval.'
  desc 'check', 'Determine if there are users defined in Forescout that are not authorized to change the software libraries.

Verify that Administrator privileges have been restricted for these users.

This is verified by reviewing the administrator account profiles and auditing the assigned privilege for updated Forescout software.

1. Log on to the Forescout Console and select Tools >> Options >> Console User Profiles.
2. Select the user group that is not authorized access according to the SSP. 
3. Select "Edit" and the "Permissions" tab
4. Verify the users do not have the "Plugin Management" and "Software Upgrade" options selected.

If Forescout is not configured to limit privileges to change the software resident within software libraries for unauthorized users, this is a finding.'
  desc 'fix', 'Configure Forescout to prevent access to change the software resident within software libraries for unauthorized personnel.

View each of the Forescout user group accounts that are associated with the external user directory groups (e.g., RADIUS, Active directory, LDAP). Perform the following actions for each group.

1. Log on to the Forescout Console and select Tools >> Options >> Console User Profiles.
2. Select the user group that is not authorized access according to the SSP. 
3. Select "Edit" and the "Permissions" tab.
4. Unselect the options for "Module Management" and "Software Upgrade".'
  impact 0.5
  ref 'DPMS Target Forescout Network Device Management'
  tag check_id: 'C-33880r603689_chk'
  tag severity: 'medium'
  tag gid: 'V-230950'
  tag rid: 'SV-230950r615886_rule'
  tag stig_id: 'FORE-NM-000230'
  tag gtitle: 'SRG-APP-000133-NDM-000244'
  tag fix_id: 'F-33853r615874_fix'
  tag 'documentable'
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']
end
