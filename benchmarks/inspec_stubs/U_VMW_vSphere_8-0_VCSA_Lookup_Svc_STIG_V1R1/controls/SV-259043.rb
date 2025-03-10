control 'SV-259043' do
  title 'The vCenter Lookup service must disable stack tracing.'
  desc 'Stack tracing provides debugging information from the application call stacks when a runtime error is encountered. If stack tracing is left enabled, Tomcat will provide this call stack information to the requestor, which could result in the loss of sensitive information or data that could be used to compromise the system.'
  desc 'check', %q(At the command prompt, run the following command:

# xmllint --xpath "//Connector[@allowTrace = 'true']" /usr/lib/vmware-lookupsvc/conf/server.xml

Expected result:

XPath set is empty

If any connectors are returned, this is a finding.)
  desc 'fix', %q(Navigate to and open:

/usr/lib/vmware-lookupsvc/conf/server.xml

Navigate to and locate:

'allowTrace="true"'

Remove the 'allowTrace="true"' setting.

Note: If "allowTrace" is not present, it defaults to "false".

Restart the service with the following command:

# vmon-cli --restart lookupsvc)
  impact 0.5
  ref 'DPMS Target VMware vSphere 8.0 VCSA Lookup Service'
  tag check_id: 'C-62783r934785_chk'
  tag severity: 'medium'
  tag gid: 'V-259043'
  tag rid: 'SV-259043r934787_rule'
  tag stig_id: 'VCLU-80-000036'
  tag gtitle: 'SRG-APP-000141-AS-000095'
  tag fix_id: 'F-62692r934786_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
