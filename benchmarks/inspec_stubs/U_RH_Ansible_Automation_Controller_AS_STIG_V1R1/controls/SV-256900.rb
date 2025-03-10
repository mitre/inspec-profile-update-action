control 'SV-256900' do
  title 'Automation Controller must use external log providers that can collect user activity logs in independent, protected repositories to prevent modification or repudiation.'
  desc 'Automation Controller must be configured to use external logging to compile log records from multiple components within the server. The events occurring must be time-correlated in order to conduct accurate forensic analysis. In addition, the correlation must meet certain tolerance criteria. For instance, DOD may define that the time stamps of different logged events must not differ by any amount greater than ten seconds. Automation Controller must utilize an external logging tool that provides this capability.

'
  desc 'check', 'Log in to Automation Controller as an administrator.

Navigate to Settings >> System >> Logging setting.

The following parameters must be set:

Enable External Logging = On

Logging Aggregator Level Threshold = DEBUG

TCP Connection Timeout = 5 (default) or the organizational timeout

Enable/disable HTTPS certificate verification = On

Logging Aggregator <> (Default) "Not configured"

If any of these settings are incorrect, this is a finding.'
  desc 'fix', 'Log in to Automation Controller as an administrator.

Navigate to Settings >> System >> Logging setting.

Click "Edit" and set the following fields:

Enable External Logging = On

Logging Aggregator Level Threshold = DEBUG

TCP Connection Timeout = 5 (default) or the organizational timeout

Enable/disable HTTPS certificate verification = On

Logging Aggregator <> (Default) "Not configured"

Click "Save".'
  impact 0.5
  ref 'DPMS Target Red Hat Ansible Automation Controller App Server'
  tag check_id: 'C-60575r902268_chk'
  tag severity: 'medium'
  tag gid: 'V-256900'
  tag rid: 'SV-256900r903512_rule'
  tag stig_id: 'APAS-AT-000017'
  tag gtitle: 'SRG-APP-000080-AS-000045'
  tag fix_id: 'F-60517r903512_fix'
  tag satisfies: ['SRG-APP-000080-AS-000045', 'SRG-APP-000086-AS-000048', 'SRG-APP-000108-AS-000067', 'SRG-APP-000125-AS-000084', 'SRG-APP-000181-AS-000255', 'SRG-APP-000358-AS-000064', 'SRG-APP-000505-AS-000230', 'SRG-APP-000506-AS-000231', 'SRG-APP-000515-AS-000203']
  tag 'documentable'
  tag cci: ['CCI-000139', 'CCI-000166', 'CCI-000172', 'CCI-000174', 'CCI-001348', 'CCI-001851', 'CCI-001876']
  tag nist: ['AU-5 a', 'AU-10', 'AU-12 c', 'AU-12 (1)', 'AU-9 (2)', 'AU-4 (1)', 'AU-7 a']
end
