control 'SV-254096' do
  title 'Innoslate must generate audit records when DoD required events occur.'
  desc 'Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident, or identify those responsible for one. 

Audit records can be generated from various components within the information system (e.g., module or policy filter).

1. Access Innoslate folder.
2. Navigate to Innoslate4\\apache-tomcat\\logs.
3. View the logs.

'
  desc 'check', '1. Locate the logging.properties file in the following directory: Innoslate\\apache-tomcat\\conf.
2. Modify lines 25, 29, 33, and 41 to be set to DEBUG or VERBOSE as needed.
3. If after a service restart the logs do not change, this is a finding.'
  desc 'fix', '1. Locate the logging.properties file in the following directory: Innoslate\\apache-tomcat\\conf.
2. Modify lines 25, 29, 33, and 41 to be set to DEBUG or VERBOSE as needed.'
  impact 0.5
  ref 'DPMS Target SPEC Innovations Innoslate 4.x'
  tag check_id: 'C-57581r845262_chk'
  tag severity: 'medium'
  tag gid: 'V-254096'
  tag rid: 'SV-254096r845264_rule'
  tag stig_id: 'SPEC-IN-001130'
  tag gtitle: 'SRG-APP-000495'
  tag fix_id: 'F-57532r845263_fix'
  tag satisfies: ['SRG-APP-000495', 'SRG-APP-000496', 'SRG-APP-000497', 'SRG-APP-000498', 'SRG-APP-000499', 'SRG-APP-000500', 'SRG-APP-000501', 'SRG-APP-000502', 'SRG-APP-000503']
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
