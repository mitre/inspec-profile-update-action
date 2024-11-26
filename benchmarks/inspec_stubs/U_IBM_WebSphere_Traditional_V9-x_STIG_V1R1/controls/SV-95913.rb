control 'SV-95913' do
  title 'The WebSphere Application Server administrative security must be enabled.'
  desc 'In previous releases of WebSphere® Application Server, when a user enabled global security, both administrative and application security were enabled.  The previous notion of global security is split into administrative security and application security, each of which you can enable separately.

As a result of this split, WebSphere Application Server clients must know whether application security is disabled at the target server. Administrative security is enabled, by default. Application security is disabled, by default. Before you can enable application security, you must verify that administrative security is enabled. Application security is in effect only when administrative security is enabled.'
  desc 'check', 'From the administrative console, click Security >> Global Security.

If "Enable administrative security" is not selected, this is a finding.'
  desc 'fix', 'From the administrative console, click Security >> Global Security.

Click "Enable administrative security".

Click "Save".

Restart the DMGR and all the JVMs.'
  impact 0.7
  ref 'DPMS Target WebSphere AS 9.x'
  tag check_id: 'C-80869r1_chk'
  tag severity: 'high'
  tag gid: 'V-81199'
  tag rid: 'SV-95913r1_rule'
  tag stig_id: 'WBSP-AS-000130'
  tag gtitle: 'SRG-APP-000315-AS-000094'
  tag fix_id: 'F-87977r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002314']
  tag nist: ['AC-17 (1)']
end
