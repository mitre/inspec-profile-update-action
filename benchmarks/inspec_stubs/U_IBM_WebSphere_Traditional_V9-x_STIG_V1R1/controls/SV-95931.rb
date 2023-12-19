control 'SV-95931' do
  title 'The WebSphere Application Server global application security must be enabled.'
  desc 'Application security enables security for the applications in your environment. This setting provides application isolation and meets security requirements such as using SSL for authenticating application users.

In previous releases of WebSphere® Application Server, when a user enabled global security, both administrative and application security were enabled. The previous notion of global security is split into administrative security and application security, each of which you can enable separately.

As a result of this split, WebSphere Application Server clients must know whether application security is disabled at the target server. Administrative security is enabled, by default. Application security is disabled, by default. Before you can enable application security, you must verify that administrative security is enabled. Application security is in effect only when administrative security is enabled.

'
  desc 'check', 'From the administrative console, navigate to Security >> Global Security.

If "Enable administrative security" and "Enable application security" are not selected, this is a finding.'
  desc 'fix', 'From the administrative console, navigate to Security >> Global Security.

Click on "Enable administrative security".

Click on "Enable application security".

Click "OK".

Click "Save".

Restart the DMGR and all the JVMs.'
  impact 0.7
  ref 'DPMS Target WebSphere AS 9.x'
  tag check_id: 'C-80889r1_chk'
  tag severity: 'high'
  tag gid: 'V-81217'
  tag rid: 'SV-95931r1_rule'
  tag stig_id: 'WBSP-AS-000170'
  tag gtitle: 'SRG-APP-000014-AS-000009'
  tag fix_id: 'F-87997r2_fix'
  tag satisfies: ['SRG-APP-000014-AS-000009', 'SRG-APP-000172-AS-000120']
  tag 'documentable'
  tag cci: ['CCI-000068', 'CCI-000197']
  tag nist: ['AC-17 (2)', 'IA-5 (1) (c)']
end
