control 'SV-240875' do
  title 'tc Server HORIZON must set sslEnabledProtocols to an approved Transport Layer Security (TLS) version.'
  desc 'Transport Layer Security (TLS) is a required transmission protocol for a web server hosting controlled information. The use of TLS provides confidentiality of data in transit between the web server and client. FIPS 140-2 approved TLS versions must be enabled and non-FIPS-approved SSL versions must be disabled.

NIST SP 800-52 defines the approved TLS versions for government applications.

tc Server connections are managed by the Connector object class. The Connector object can be configured to use a range of transport encryption methods. Many older transport encryption methods have been proven to be weak. vRA should be configured to use the sslEnabledProtocols correctly to ensure that older, less secure forms of transport security are not used.'
  desc 'check', 'Navigate to and open /opt/vmware/horizon/workspace/conf/server.xml.

Navigate to each of the <Connector> nodes.

If the value of "sslEnabledProtocols" is not set to "TLSv1.2,TLSv1.1,TLSv1" or is missing, this is a finding.'
  desc 'fix', %q(Navigate to and open /opt/vmware/horizon/workspace/conf/server.xml.

Navigate to each of the <Connector> nodes.

Note: There are three <Connector> nodes.

Configure each <Connector> node with the setting 'sslEnabledProtocols="TLSv1.2,TLSv1.1,TLSv1"'.)
  impact 0.7
  ref 'DPMS Target VMware vRealize Automation 7-x tc Server'
  tag check_id: 'C-44108r674367_chk'
  tag severity: 'high'
  tag gid: 'V-240875'
  tag rid: 'SV-240875r879810_rule'
  tag stig_id: 'VRAU-TC-000915'
  tag gtitle: 'SRG-APP-000439-WSR-000156'
  tag fix_id: 'F-44067r674368_fix'
  tag 'documentable'
  tag legacy: ['SV-100829', 'V-90179']
  tag cci: ['CCI-002418']
  tag nist: ['SC-8']
end
