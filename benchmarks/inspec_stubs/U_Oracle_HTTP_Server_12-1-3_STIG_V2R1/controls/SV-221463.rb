control 'SV-221463' do
  title 'OHS administration must be performed over a secure path or at the local console.'
  desc 'Logging into a web server remotely using an unencrypted protocol or service when performing updates and maintenance is a major risk.  Data, such as user account, is transmitted in plaintext and can easily be compromised.  When performing remote administrative tasks, a protocol or service that encrypts the communication channel must be used.
 
An alternative to remote administration of the web server is to perform web server administration locally at the console.  Local administration at the console implies physical access to the server.'
  desc 'check', '1. Check that if server administration is performed remotely, it will only be performed securely by system administrators.

2. Check that if OHS administration has been delegated, those users will be documented and approved by the ISSO.

3. Check that remote administration is in compliance with any requirements contained within the Unix Server STIGs and any applicable network STIGs.

4. Check that remote administration of any kind will be restricted to documented and authorized personnel and that all users performing remote administration are authenticated.

5. Check that all remote sessions will be encrypted and utilize FIPS 140-2 approved protocols.

6. If any of the above conditions are not met, this is a finding.'
  desc 'fix', 'Ensure that both system and OHS administration are done through a secure path.'
  impact 0.7
  ref 'DPMS Target Oracle HTTP Server 12.1.3'
  tag check_id: 'C-23178r415072_chk'
  tag severity: 'high'
  tag gid: 'V-221463'
  tag rid: 'SV-221463r415074_rule'
  tag stig_id: 'OH12-1X-000226'
  tag gtitle: 'SRG-APP-000516-WSR-000174'
  tag fix_id: 'F-23167r415073_fix'
  tag 'documentable'
  tag legacy: ['SV-79179', 'V-64689']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
