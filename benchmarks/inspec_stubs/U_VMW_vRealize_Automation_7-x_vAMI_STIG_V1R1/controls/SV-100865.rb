control 'SV-100865' do
  title 'The vAMI installation procedures must be capable of being rolled back to a last known good configuration.'
  desc 'Any changes to the components of the application server can have significant effects on the overall security of the system. In order to ensure a prompt response to failed application installations and application server upgrades, the application server must provide an automated rollback capability that allows the system to be restored to a previous known good configuration state prior to the application installation or application server upgrade.'
  desc 'check', 'Interview the ISSO and/or the SA.

Determine if there is a local procedure to revert to the last known good configuration in the event of failed installations and upgrades.

If a procedure does not exist or is not being followed, this is a finding.'
  desc 'fix', 'Develop and implement a site procedure to revert to the last known good configuration in the event of failed installations and upgrades.'
  impact 0.5
  ref 'DPMS Target vRealize Automation 7.x VAMI'
  tag check_id: 'C-89907r1_chk'
  tag severity: 'medium'
  tag gid: 'V-90215'
  tag rid: 'SV-100865r1_rule'
  tag stig_id: 'VRAU-VA-000180'
  tag gtitle: 'SRG-APP-000133-AS-000093'
  tag fix_id: 'F-96957r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']
end
