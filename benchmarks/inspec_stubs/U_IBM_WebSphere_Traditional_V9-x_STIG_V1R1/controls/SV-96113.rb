control 'SV-96113' do
  title 'The WebSphere Application Server must apply the latest security fixes.'
  desc 'Security vulnerabilities are often addressed by testing and applying the latest security patches and fix packs. Latest fixpacks can be found at: http://www-01.ibm.com/support/docview.wss?uid=swg27009661'
  desc 'check', 'Use the admin console to determine the WebSphere version.

Review patch level and fix pack.

If the most recent patches/fix packs have not been applied, this is a finding.'
  desc 'fix', 'Obtain WebSphere product security and patch support.

Test and apply the latest applicable WebSphere security fixes.'
  impact 0.5
  ref 'DPMS Target WebSphere AS 9.x'
  tag check_id: 'C-81109r1_chk'
  tag severity: 'medium'
  tag gid: 'V-81399'
  tag rid: 'SV-96113r1_rule'
  tag stig_id: 'WBSP-AS-001750'
  tag gtitle: 'SRG-APP-000456-AS-000266'
  tag fix_id: 'F-88185r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002605']
  tag nist: ['SI-2 c']
end
