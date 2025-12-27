control 'SV-256902' do
  title 'Automation Controller must be configured to fail over to another system in the event of log subsystem failure.'
  desc 'Automation Controller hosts must be capable of failing over to another Automation Controller host which can handle application and logging functions upon detection of an application log processing failure. This will allow continual operation of the application and logging functions while minimizing the loss of operation for the users and loss of log data.

'
  desc 'check', 'The Administrator must check the Automation Controller is deployed in an HA configuration. 

Administrator must check Automation Controller host via the REST API at api/v2/ping/ HA field for HA configuration. 

If this field is not true, indicating Automation Controller is in an HA configuration, this is a finding.'
  desc 'fix', 'If Automation Controller is not in an HA configuration, the administrator must reinstall Automation Controller.'
  impact 0.5
  ref 'DPMS Target Red Hat Ansible Automation Controller App Server'
  tag check_id: 'C-60577r902274_chk'
  tag severity: 'medium'
  tag gid: 'V-256902'
  tag rid: 'SV-256902r902276_rule'
  tag stig_id: 'APAS-AT-000032'
  tag gtitle: 'SRG-APP-000109-AS-000070'
  tag fix_id: 'F-60519r902275_fix'
  tag satisfies: ['SRG-APP-000109-AS-000070', 'SRG-APP-000225-AS-000154', 'SRG-APP-000435-AS-000069']
  tag 'documentable'
  tag cci: ['CCI-000140', 'CCI-001190', 'CCI-002385']
  tag nist: ['AU-5 b', 'SC-24', 'SC-5 a']
end
