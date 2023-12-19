control 'SV-222662' do
  title 'Default passwords must be changed.'
  desc 'Default passwords can easily be compromised by attackers allowing immediate access to the applications.'
  desc 'check', 'Identify the application name and version and do an Internet search for the product name and the string "default password".

If default passwords are found, attempt to authenticate with the published default passwords.

If authentication is successful, this is a finding.'
  desc 'fix', 'Configure the application to use strong authenticators instead of passwords when possible. Otherwise, change default passwords to a DoD-approved strength password and follow all guidance for passwords.'
  impact 0.7
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-24332r493894_chk'
  tag severity: 'high'
  tag gid: 'V-222662'
  tag rid: 'SV-222662r879887_rule'
  tag stig_id: 'APSC-DV-003280'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-24321r493895_fix'
  tag 'documentable'
  tag legacy: ['SV-85025', 'V-70403']
  tag cci: ['CCI-003109']
  tag nist: ['SA-4 (5) (a)']
end
