control 'SV-222637' do
  title 'Recovery procedures and technical system features must exist so recovery is performed in a secure and verifiable manner. The ISSO will document circumstances inhibiting a trusted recovery.'
  desc 'Without a disaster recovery plan, the application is susceptible to interruption in service due to damage within the processing site.

If the application is part of the site’s disaster recovery plan, ensure that the plan contains detailed instructions pertaining to the application. Verify that recovery procedures indicate the steps needed for secure and trusted recovery.'
  desc 'check', 'Review disaster recovery plan.

Verify that a disaster recovery plan is in place for the application.

Verify that the recovery procedures include any special considerations for trusted recovery.

If the application is not part of the site’s disaster recovery plan, or if any special considerations for trusted recovery are not documented, this is a finding.'
  desc 'fix', 'Create and maintain a disaster recovery plan.'
  impact 0.5
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-24307r493819_chk'
  tag severity: 'medium'
  tag gid: 'V-222637'
  tag rid: 'SV-222637r864420_rule'
  tag stig_id: 'APSC-DV-003060'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-24296r493820_fix'
  tag 'documentable'
  tag legacy: ['SV-84975', 'V-70353']
  tag cci: ['CCI-000448']
  tag nist: ['CP-2 a 2']
end
