control 'SV-204796' do
  title 'The application server must enforce access restrictions associated with changes to application server configuration.'
  desc "When dealing with access restrictions pertaining to change control, it should be noted that any changes to the software, and/or application server configuration can potentially have significant effects on the overall security of the system.

Access restrictions for changes also include application software libraries.

If the application server provides automatic code deployment capability, (where updates to applications hosted on the application server are automatically performed, usually by the developers' IDE tool), it must also provide a capability to restrict the use of automatic application deployment. Automatic code deployments are allowable in a development environment, but not in production."
  desc 'check', 'Review the application server documentation and configuration to determine if the system employs mechanisms to enforce restrictions on application server configuration changes.

Configuration changes include, but are not limited to, automatic code deployments, software library updates, and changes to configuration settings within the application server.

If the application server does not enforce access restrictions for configuration changes, this is a finding.'
  desc 'fix', 'Configure the application server to enforce access restrictions associated with changes to the application server configuration to include code deployment, library updates, and changes to application server configuration settings.'
  impact 0.5
  ref 'DPMS Target Application Server'
  tag check_id: 'C-4916r283035_chk'
  tag severity: 'medium'
  tag gid: 'V-204796'
  tag rid: 'SV-204796r850851_rule'
  tag stig_id: 'SRG-APP-000380-AS-000088'
  tag gtitle: 'SRG-APP-000380'
  tag fix_id: 'F-4916r283036_fix'
  tag 'documentable'
  tag legacy: ['V-57491', 'SV-71767']
  tag cci: ['CCI-001813']
  tag nist: ['CM-5 (1) (a)']
end
