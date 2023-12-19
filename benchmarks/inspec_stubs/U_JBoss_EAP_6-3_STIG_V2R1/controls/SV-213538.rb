control 'SV-213538' do
  title 'Network access to HTTP management must be disabled on domain-enabled application servers not designated as the domain controller.'
  desc 'When configuring JBoss application servers into a domain configuration, HTTP management capabilities are not required on domain member servers as management is done via the server that has been designated as the domain controller. 

Leaving HTTP management capabilities enabled on domain member servers increases the attack surfaces; therefore, management services on domain member servers must be disabled and management services performed via the domain controller.'
  desc 'check', 'Log on to each of the JBoss domain member servers.

Note: Sites that manage systems using the JBoss Operations Network client require HTTP interface access.  It is acceptable that the management console alone be disabled rather than disabling the entire interface itself.

Run the <JBOSS_HOME>/bin/jboss-cli command line interface utility and connect to the JBoss server.
Run the following command:
ls /core-service=management/management-interface=httpinterface/

If "console-enabled=true", this is a finding.'
  desc 'fix', 'Run the <JBOSS_HOME>/bin/jboss-cli command line interface utility. 
Connect to the JBoss server and run the following command.
/core-service=management/management-interface=httpinterface/:write-attribute(name=console-enabled,value=false)

Successful command execution returns
{"outcome" => "success"}, and future attempts to access the management console via web browser at <SERVERNAME>:9990 will result in no access to the admin console.'
  impact 0.5
  ref 'DPMS Target JBoss Enterprise Application Platform 6.3'
  tag check_id: 'C-14761r296280_chk'
  tag severity: 'medium'
  tag gid: 'V-213538'
  tag rid: 'SV-213538r615939_rule'
  tag stig_id: 'JBOS-AS-000470'
  tag gtitle: 'SRG-APP-000316-AS-000199'
  tag fix_id: 'F-14759r296281_fix'
  tag 'documentable'
  tag legacy: ['SV-76793', 'V-62303']
  tag cci: ['CCI-002322']
  tag nist: ['AC-17 (9)']
end
