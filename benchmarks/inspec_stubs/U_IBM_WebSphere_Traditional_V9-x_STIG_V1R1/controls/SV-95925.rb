control 'SV-95925' do
  title 'The WebSphere Application Server audit service provider must be enabled.'
  desc 'Logging must be utilized in order to track system activity, assist in diagnosing system issues, and provide evidence needed for forensic investigations post security incident.

Remote access by administrators requires that the admin activity be logged.

Application servers provide a web and command line-based remote management capability for managing the application server. Application servers must ensure that all actions related to administrative functionality such as application server configuration are logged.

'
  desc 'check', 'In the administrative console, navigate to Security >> Security auditing >> Audit Service Provider [provider name]. 

Under "Enabled filters", determine if the filter name from select the name of the filter that was recorded from STIG ID WBSP-AS-000100.

If the filter that was identified in STIG ID WBSP-AS-000100 is not enabled, this is a finding.'
  desc 'fix', 'In the administrative console, navigate to Security >> Security auditing >> Event type Filters.

Identify and record the event type filter that contains the required "Events and Outcomes".

In the administrative console, click on Security >> Security auditing >> Audit Service Provider [provider name]. 

Under "Selectable filters", select the filter that was previously identified and recorded.

Click the right arrow to add it to the list.

Click "OK".

Click "Save" to save the changes.

Restart the DMGR and all the JVMs.'
  impact 0.5
  ref 'DPMS Target WebSphere AS 9.x'
  tag check_id: 'C-80881r1_chk'
  tag severity: 'medium'
  tag gid: 'V-81211'
  tag rid: 'SV-95925r1_rule'
  tag stig_id: 'WBSP-AS-000110'
  tag gtitle: 'SRG-APP-000016-AS-000013'
  tag fix_id: 'F-87989r1_fix'
  tag satisfies: ['SRG-APP-000016-AS-000013', 'SRG-APP-000343-AS-000030']
  tag 'documentable'
  tag cci: ['CCI-000067', 'CCI-002234']
  tag nist: ['AC-17 (1)', 'AC-6 (9)']
end
