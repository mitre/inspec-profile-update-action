control 'SV-213542' do
  title 'Production JBoss servers must not allow automatic application deployment.'
  desc "When dealing with access restrictions pertaining to change control, it should be noted that any changes to the software and/or application server configuration can potentially have significant effects on the overall security of the system.

Access restrictions for changes also include application software libraries.

If the application server provides automatic code deployment capability, (where updates to applications hosted on the application server are automatically performed, usually by the developers' IDE tool), it must also provide a capability to restrict the use of automatic application deployment. Automatic code deployments are allowable in a development environment, but not in production."
  desc 'check', 'Log on to the OS of the JBoss server with OS permissions that allow access to JBoss.
Using the relevant OS commands and syntax, cd to the <JBOSS_HOME>/bin/ folder.
Run the jboss-cli script.
Connect to the server and authenticate.
Run the command:

ls /subsystem=deployment-scanner/scanner=default

If "scan-enabled"=true, this is a finding.'
  desc 'fix', 'Determine the JBoss server configuration as being either standalone or domain.

Launch the relevant jboss-cli management interface substituting standalone or domain for <CONFIG>

<JBOSS_HOME>/<CONFIG>/bin/jboss-cli

connect to the server and run the command:

/subsystem=deployment-scanner/scanner=default:write-attribute(name=scan-enabled,value=false)'
  impact 0.5
  ref 'DPMS Target JBoss Enterprise Application Platform 6.3'
  tag check_id: 'C-14765r296292_chk'
  tag severity: 'medium'
  tag gid: 'V-213542'
  tag rid: 'SV-213542r615939_rule'
  tag stig_id: 'JBOS-AS-000545'
  tag gtitle: 'SRG-APP-000380-AS-000088'
  tag fix_id: 'F-14763r296293_fix'
  tag 'documentable'
  tag legacy: ['SV-76801', 'V-62311']
  tag cci: ['CCI-001813']
  tag nist: ['CM-5 (1) (a)']
end
