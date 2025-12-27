control 'SV-204749' do
  title 'The application server must provide security extensions to extend the SOAP protocol and provide secure authentication when accessing sensitive data.'
  desc 'Application servers may provide a web services capability that could be leveraged to allow remote access to sensitive application data. A web service, which is a repeatable process used to make data available to remote clients, should not be confused with a web server. 

Many web services utilize SOAP, which in turn utilizes XML and HTTP as a transport. Natively, SOAP does not provide security protections. As such, the application server must provide security extensions to enhance SOAP capabilities to ensure that secure authentication mechanisms are employed to protect sensitive data. The WS_Security suite is a widely used and acceptable SOAP security extension.'
  desc 'check', 'Review application server documentation to ensure the application server provides extensions to the SOAP protocol that provide secure authentication. These protocols include, but are not limited to, WS_Security suite.  Review policy and data owner protection requirements in order to identify sensitive data.

If secure authentication protocols are not utilized to protect data identified by data owner as requiring protection, this is a finding.'
  desc 'fix', 'Configure the application server to utilize secure authentication when SOAP web services are used to access sensitive data.'
  impact 0.5
  ref 'DPMS Target Application Server'
  tag check_id: 'C-4869r282894_chk'
  tag severity: 'medium'
  tag gid: 'V-204749'
  tag rid: 'SV-204749r850831_rule'
  tag stig_id: 'SRG-APP-000156-AS-000106'
  tag gtitle: 'SRG-APP-000156'
  tag fix_id: 'F-4869r282895_fix'
  tag 'documentable'
  tag legacy: ['V-35304', 'SV-46591']
  tag cci: ['CCI-001941']
  tag nist: ['IA-2 (8)']
end
