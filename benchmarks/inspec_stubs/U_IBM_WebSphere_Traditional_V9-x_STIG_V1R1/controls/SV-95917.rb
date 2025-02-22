control 'SV-95917' do
  title 'The WebSphere Application Server security auditing must be enabled.'
  desc 'Security auditing will not be performed unless the audit security subsystem has been enabled. Global security must be enabled for the security audit subsystem to function, as no security auditing occurs if global security is not also enabled. Enable global security before enabling security auditing.

'
  desc 'check', 'In the administrative console, navigate to Security >> Security auditing.

If "Enable security auditing" is not enabled, this is a finding.'
  desc 'fix', 'In the administrative console, navigate to Security >> Security auditing to enable.

Restart the DMGR and all the JVMs.'
  impact 0.5
  ref 'DPMS Target WebSphere AS 9.x'
  tag check_id: 'C-80873r1_chk'
  tag severity: 'medium'
  tag gid: 'V-81203'
  tag rid: 'SV-95917r1_rule'
  tag stig_id: 'WBSP-AS-000070'
  tag gtitle: 'SRG-APP-000016-AS-000013'
  tag fix_id: 'F-87981r1_fix'
  tag satisfies: ['SRG-APP-000016-AS-000013', 'SRG-APP-000343-AS-000030', 'SRG-APP-000080-AS-000045', 'SRG-APP-000092-AS-000053', 'SRG-APP-000266-AS-000168', 'SRG-APP-000267-AS-000170']
  tag 'documentable'
  tag cci: ['CCI-000067', 'CCI-000166', 'CCI-001312', 'CCI-001314', 'CCI-001464', 'CCI-002234']
  tag nist: ['AC-17 (1)', 'AU-10', 'SI-11 a', 'SI-11 b', 'AU-14 (1)', 'AC-6 (9)']
end
