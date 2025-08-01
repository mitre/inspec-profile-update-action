control 'SV-95923' do
  title 'The WebSphere Application Server audit event type filters must be configured.'
  desc 'Logging must be utilized in order to track system activity, assist in diagnosing system issues, and provide evidence needed for forensic investigations post security incident.

Remote access by administrators requires that the admin activity be logged.

Application servers provide a web and command line-based remote management capability for managing the application server. Application servers must ensure that all actions related to administrative functionality such as application server configuration are logged.

'
  desc 'check', 'In the administrative console, navigate to Security >> Security auditing >> Event type Filters.

Verify the following events and outcomes are enabled in the "Events and Outcomes" box. Also note the name of the filter associated with these events. This name will be referenced in STIG ID WBSP-AS-000110.

AUTHN: 
SUCCESS,INFO,WARNING,ERROR,DENIED,REDIRECT

AUTHZ: 
SUCCESS,INFO,WARNING,ERROR,DENIED,REDIRECT

AUTHN_TERMINATE:
SUCCESS,INFO,WARNING,ERROR,DENIED,REDIRECT

REPOSITORY_SAVE: SUCCESS,INFO,WARNING,ERROR,DENIED,REDIRECT

If these audit filters are not configured in "Events and Outcomes", this is a finding.'
  desc 'fix', 'In the administrative console, navigate to Security >> Security auditing >> Event type Filters.

Click the "New" button to create a new filter; give it a unique name. 

Select SECURITY_AUTHN, SECURITY_AUTHZ, SECURITY_AUTHN_TERMINATE, and ADMIN_REPOSITORY_SAVE from "Selectable events".

Add them to the "Enabled events" box by clicking on the right arrow. 

Select INFO, ERROR, SUCCESS, DENIED, REDIRECT, and WARNING from the "Selectable event outcomes" box.

Click the right arrow to fill in "Enabled events outcomes" box.

Click "OK". 

Restart the DMGR and all the JVMs.'
  impact 0.5
  ref 'DPMS Target WebSphere AS 9.x'
  tag check_id: 'C-80879r1_chk'
  tag severity: 'medium'
  tag gid: 'V-81209'
  tag rid: 'SV-95923r1_rule'
  tag stig_id: 'WBSP-AS-000100'
  tag gtitle: 'SRG-APP-000016-AS-000013'
  tag fix_id: 'F-87987r1_fix'
  tag satisfies: ['SRG-APP-000016-AS-000013', 'SRG-APP-000343-AS-000030', 'SRG-APP-000089-AS-000050', 'SRG-APP-000495-AS-000220', 'SRG-APP-000499-AS-000224', 'SRG-APP-000503-AS-000228', 'SRG-APP-000504-AS-000229', 'SRG-APP-000505-AS-000230', 'SRG-APP-000506-AS-000231', 'SRG-APP-000093-AS-000054', 'SRG-APP-000095-AS-000056', 'SRG-APP-000097-AS-000060', 'SRG-APP-000098-AS-000061', 'SRG-APP-000099-AS-000062', 'SRG-APP-000100-AS-000063', 'SRG-APP-000101-AS-000072', 'SRG-APP-000381-AS-000089', 'SRG-APP-000080-AS-000045']
  tag 'documentable'
  tag cci: ['CCI-000067', 'CCI-000130', 'CCI-000132', 'CCI-000133', 'CCI-000134', 'CCI-000135', 'CCI-000169', 'CCI-000172', 'CCI-001462', 'CCI-001487', 'CCI-001814', 'CCI-002234']
  tag nist: ['AC-17 (1)', 'AU-3 a', 'AU-3 c', 'AU-3 d', 'AU-3 e', 'AU-3 (1)', 'AU-12 a', 'AU-12 c', 'AU-14 (2)', 'AU-3 f', 'CM-5 (1)', 'AC-6 (9)']
end
