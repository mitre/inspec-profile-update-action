control 'SV-96057' do
  title 'The WebSphere Application Server application security must be enabled for each security domain except for publicly available applications specified in the System Security Plan.'
  desc 'By default, all administrative and user applications in WebSphere® Application Server use the global security configuration. For example, a user registry defined in global security is used to authenticate users for every application in the cell. WebSphere allows for additional WebSphere security domains where different security attributes for some or all of your user applications can be set. These domains must also be configured to use application security.'
  desc 'check', 'Review System Security Plan documentation.

Identify any publicly available applications. These are applications available to the public that do not require authentication to access (e.g., recruiting websites).

If such applications exist on the system and are specifically allowed according to the security plan, this requirement is NA for those applications only.

Navigate to security >> security domains.

Click through each security domain.

If "Customize for this domain" is checked for Application Security under the Security Attributes, but "Enable application security" is not checked, this is a finding.'
  desc 'fix', 'Navigate to security >> security domains.

Click through each security domain.

If "Customize for this domain" is checked for Application Security under the Security Attributes, but "Enable application security" is not checked, check "Enable application security".

Expand "show" to find all affected nodes and servers.

Click "OK".

Click "Save".

Synchronize the changes.

Restart all affected nodes and servers.'
  impact 0.7
  ref 'DPMS Target WebSphere AS 9.x'
  tag check_id: 'C-81049r2_chk'
  tag severity: 'high'
  tag gid: 'V-81343'
  tag rid: 'SV-96057r1_rule'
  tag stig_id: 'WBSP-AS-001180'
  tag gtitle: 'SRG-APP-000172-AS-000120'
  tag fix_id: 'F-88127r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000197']
  tag nist: ['IA-5 (1) (c)']
end
