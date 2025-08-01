control 'SV-230954' do
  title 'If the network device uses role-based access control, Forescout must enforce organization-defined, role-based access control policies over defined subjects and objects.'
  desc 'Organizations can create specific roles based on job functions and the authorizations (i.e., privileges) to perform needed operations on organizational information systems associated with the organization-defined roles. When administrators are assigned to the organizational roles, they inherit the authorizations or privileges defined for those roles. 

Forescout has three predefined user roles: Admin, Web Access, and Console User. The Admin role has access to all data and management functions. 

By default, the Console role has access to the management console and the Web role has access to the view-only portal. However, both roles may be assigned one or more permissions, each with its own set of privileges to the data and functions.'
  desc 'check', "Check the administrative accounts assigned to each role are documented within the SSP and have been configured correctly with least privilege.

1. Log on to Forescout UI.
2. Select Tools >> Options >> CounterACT User Profiles.
3. Select username >> Edit >> Permissions.

Check the SSP against created users and ensure least privilege has been configured properly. Options include Custom accounts for Console Access and Web Access. Each access account is then further established with permissions based on the user's authorizations.

If Forescout does not enforce organization-defined, role-based access control policies over defined subjects and objects, this is a finding."
  desc 'fix', "Login to Forescout UI.

1. Select Tools >> Options >> CounterACT User Profiles.
2. Select username >> Edit >> Permissions.

Check the SSP against created users and ensure least privilege has been configured properly. Options include Custom accounts for Console Access and Web Access. Each access account is then further established with permissions based on the user's authorizations."
  impact 0.5
  ref 'DPMS Target Forescout Network Device Management'
  tag check_id: 'C-33884r603701_chk'
  tag severity: 'medium'
  tag gid: 'V-230954'
  tag rid: 'SV-230954r616548_rule'
  tag stig_id: 'FORE-NM-000270'
  tag gtitle: 'SRG-APP-000329-NDM-000287'
  tag fix_id: 'F-33857r603702_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-002169']
  tag nist: ['CM-6 b', 'AC-3 (7)']
end
