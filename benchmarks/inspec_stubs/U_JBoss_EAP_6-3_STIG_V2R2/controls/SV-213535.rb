control 'SV-213535' do
  title 'The JBoss server must separate hosted application functionality from application server management functionality.'
  desc '<0> [object Object]'
  desc 'check', 'If JBoss is not started with separate management and public interfaces, this is a finding.

Review the network design documents to identify the IP address space for the management network.  

Use relevant OS commands and administrative techniques to determine how the system administrator starts the JBoss server.  This includes interviewing the system admin, using the "ps -ef|grep" command for UNIX like systems or checking command line flags and properties on batch scripts for Windows systems.  

Ensure the startup syntax used to start JBoss specifies a management network address and a public network address.

The "-b" flag specifies the public address space.
The "-bmanagement" flag specifies the management address space.

Example:
<JBOSS_HOME>/bin/standalone.sh -bmanagement 10.10.10.35 -b 192.168.10.25

If JBoss is not started with separate management and public interfaces, this is a finding.'
  desc 'fix', 'Start the application server with a -bmanagement and a -b flag so that admin management functionality and hosted applications are separated.

Refer to section 4.9 in the JBoss EAP 6.3 Installation Guide for specific instructions on how to start the JBoss server as a service.'
  impact 0.5
  ref 'DPMS Target JBoss Enterprise Application Platform 6.3'
  tag check_id: 'C-14758r296271_chk'
  tag severity: 'medium'
  tag gid: 'V-213535'
  tag rid: 'SV-213535r615939_rule'
  tag stig_id: 'JBOS-AS-000355'
  tag gtitle: 'SRG-APP-000211-AS-000146'
  tag fix_id: 'F-14756r296272_fix'
  tag legacy: ['SV-76787', 'V-62297']
  tag cci: ['CCI-001082']
  tag nist: ['SC-2']
end
