control 'SV-95929' do
  title 'The WebSphere Application Server Quality of Protection (QoP) must be set to use TLSv1.2 or higher.'
  desc 'Quality of Protection specifies the security level, ciphers, and mutual authentication settings for the Secure Socket Layer (SSL/TLS) configuration.'
  desc 'check', 'From the administrative console, navigate to Security >> SSL certificate and key management.

Click "SSL configurations".

Click on each SSL configuration to review.

Under "Additional Properties", click "Quality of protection (QoP)" settings.

If the "Protocol" field does not show "TLSv1.2 or greater", this is a finding.'
  desc 'fix', 'From the administrative console, navigate to Security >> SSL certificate and key management.

Click "SSL configurations".

Click on each SSL configuration.

Under "Additional Properties", click "Quality of protection (QoP)" settings.

At the "Protocol" pull-down menu, select "TLSv1.2 or greater".

Click "OK".

Click "Save".

Restart the DMGR and all the JVMs.'
  impact 0.5
  ref 'DPMS Target WebSphere AS 9.x'
  tag check_id: 'C-80887r1_chk'
  tag severity: 'medium'
  tag gid: 'V-81215'
  tag rid: 'SV-95929r1_rule'
  tag stig_id: 'WBSP-AS-000160'
  tag gtitle: 'SRG-APP-000014-AS-000009'
  tag fix_id: 'F-87995r3_fix'
  tag 'documentable'
  tag cci: ['CCI-000068']
  tag nist: ['AC-17 (2)']
end
