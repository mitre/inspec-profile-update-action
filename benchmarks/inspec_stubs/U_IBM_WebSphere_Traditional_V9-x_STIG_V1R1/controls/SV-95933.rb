control 'SV-95933' do
  title 'The WebSphere Application Server Single Sign On (SSO) must have SSL enabled for Web and SIP Security.'
  desc 'Remote management access is accomplished by leveraging common communication protocols and establishing a remote connection to the application server via a network for the purposes of managing the application server. If cryptography is not used, then the session data traversing the remote connection could be intercepted and compromised. 

Types of management interfaces utilized by an application server include web-based HTTPS interfaces as well as command line-based management interfaces.

'
  desc 'check', 'From the administrative console, navigate to Security >> Global Security.

Expand "Web and SIP security".

Click on "Single sign-on (SSO)".

If "requires SSL" is not selected, this is a finding.'
  desc 'fix', 'From the administrative console, navigate to Security >> Global Security.

Expand "Web and SIP security".

Click on "Single sign-on (SSO)".

Select "Requires SSL".

Click "OK".

Click "Save".

Restart the DMGR and all the JVMs.'
  impact 0.7
  ref 'DPMS Target WebSphere AS 9.x'
  tag check_id: 'C-80891r1_chk'
  tag severity: 'high'
  tag gid: 'V-81219'
  tag rid: 'SV-95933r1_rule'
  tag stig_id: 'WBSP-AS-000180'
  tag gtitle: 'SRG-APP-000014-AS-000009'
  tag fix_id: 'F-87999r1_fix'
  tag satisfies: ['SRG-APP-000014-AS-000009', 'SRG-APP-000172-AS-000120', 'SRG-APP-000158-AS-000108']
  tag 'documentable'
  tag cci: ['CCI-000068', 'CCI-000197', 'CCI-000778']
  tag nist: ['AC-17 (2)', 'IA-5 (1) (c)', 'IA-3']
end
