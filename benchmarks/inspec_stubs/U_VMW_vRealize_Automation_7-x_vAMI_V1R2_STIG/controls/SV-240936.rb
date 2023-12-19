control 'SV-240936' do
  title 'The vAMI installation procedures must be capable of being rolled back to a last known good configuration.'
  desc 'Any changes to the components of the application server can have significant effects on the overall security of the system. In order to ensure a prompt response to failed application installations and application server upgrades, the application server must provide an automated rollback capability that allows the system to be restored to a previous known good configuration state prior to the application installation or application server upgrade.'
  desc 'check', 'Interview the ISSO and/or the SA.

Determine if there is a local procedure to revert to the last known good configuration in the event of failed installations and upgrades.

If a procedure does not exist or is not being followed, this is a finding.'
  desc 'fix', 'Develop and implement a site procedure to revert to the last known good configuration in the event of failed installations and upgrades.'
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7-x vAMI'
  tag check_id: 'C-44169r675973_chk'
  tag severity: 'medium'
  tag gid: 'V-240936'
  tag rid: 'SV-240936r879586_rule'
  tag stig_id: 'VRAU-VA-000180'
  tag gtitle: 'SRG-APP-000133-AS-000093'
  tag fix_id: 'F-44128r675974_fix'
  tag 'documentable'
  tag legacy: ['SV-100865', 'V-90215']
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']
end
