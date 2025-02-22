control 'SV-79155' do
  title 'OHS tools must be restricted to the web manager and the web managers designees.'
  desc 'All automated information systems are at risk of data loss due to disaster or compromise. Failure to provide adequate protection to the administration tools creates risk of potential theft or damage that may ultimately compromise the mission.  Adequate protection ensures that server administration operates with less risk of losses or operations outages.  The key web service administrative and configuration tools must be accessible only by the authorized web server administrators. All users granted this authority must be documented and approved by the ISSO. Access to OHS must be limited to authorized users and administrators.'
  desc 'check', '1. Determine whether anyone other than the System Administrator or the OHS Administrator has inappropriate access to modify the OHS configuration. This includes the ability to use the OS account that owns OHS, root, or a tool with OHS management or monitoring capability such as Oracle Enterprise Manager (OEM).

2. If so, this is a finding.'
  desc 'fix', 'Restrict access to the OS account that owns OHS, root, or tool with OHS management or monitoring capability such as Oracle Enterprise Manager (OEM).'
  impact 0.5
  ref 'DPMS Target Oracle HTTP Server (OHS) 12.1.x'
  tag check_id: 'C-65407r1_chk'
  tag severity: 'medium'
  tag gid: 'V-64665'
  tag rid: 'SV-79155r1_rule'
  tag stig_id: 'OH12-1X-000214'
  tag gtitle: 'SRG-APP-000516-WSR-000174'
  tag fix_id: 'F-70595r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
