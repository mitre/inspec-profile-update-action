control 'SV-241734' do
  title 'tc Server UI must set sslEnabledProtocols to an approved Transport Layer Security (TLS) version.'
  desc 'Transport Layer Security (TLS) is a required transmission protocol for a web server hosting controlled information. The use of TLS provides confidentiality of data in transit between the web server and client. FIPS 140-2 approved TLS versions must be enabled and non-FIPS-approved SSL versions must be disabled.

NIST SP 800-52 defines the approved TLS versions for government applications.

tc Server connections are managed by the Connector object class. The Connector object can be configured to use a range of transport encryption methods. Many older transport encryption methods have been proven to be weak. vROps should be configured to use the “sslEnabledProtocols” correctly to ensure that older, less secure forms of transport security are not used.'
  desc 'check', 'Navigate to and open /usr/lib/vmware-vcops/tomcat-web-app/conf/server.xml. 

Navigate to each of the <Connector> nodes.

If the value of “sslEnabledProtocols” is not set to “TLSv1.2,TLSv1.1,TLSv1” or is missing, this is a finding.'
  desc 'fix', %q(Navigate to and open /usr/lib/vmware-vcops/tomcat-web-app/conf/server.xml.

Navigate to each of the <Connector> nodes.

Configure each <Connector> node with the setting 'sslEnabledProtocols="TLSv1.2,TLSv1.1,TLSv1"')
  impact 0.7
  ref 'DPMS Target VMware vRealize Operations Manager 6-x tc Server'
  tag check_id: 'C-45010r684062_chk'
  tag severity: 'high'
  tag gid: 'V-241734'
  tag rid: 'SV-241734r879810_rule'
  tag stig_id: 'VROM-TC-000970'
  tag gtitle: 'SRG-APP-000439-WSR-000156'
  tag fix_id: 'F-44969r684063_fix'
  tag 'documentable'
  tag legacy: ['SV-99753', 'V-89103']
  tag cci: ['CCI-002418']
  tag nist: ['SC-8']
end
