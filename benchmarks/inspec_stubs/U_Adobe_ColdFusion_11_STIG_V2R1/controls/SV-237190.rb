control 'SV-237190' do
  title 'ColdFusion must provide security extensions to extend the SOAP protocol and provide secure authentication when accessing sensitive data.'
  desc 'Application servers may provide a web services capability that could be leveraged to allow remote access to sensitive application data.

Many web services utilize SOAP, which in turn utilizes XML and HTTP as a transport.  Natively, SOAP does not provide security protections. As such, the application server must provide security extensions to enhance SOAP capabilities to ensure that secure authentication mechanisms are employed to protect sensitive data. The ws-security suite is a widely used and acceptable SOAP security extension.

ColdFusion offers SOAP capabilities but does not offer any type of security for these services.  In order to extend the security of the SOAP protocol, an administrator must install the ws-security suite to enhance SOAP through Java Web Services and configure the ws-security features within the new object.  This new object then becomes the wrapper for the SOAP communication, securing the sensitive data.'
  desc 'check', 'Determine if web services are published using the SOAP protocol to  access sensitive data.  This may be determined by interviewing the administrator or by reviewing hosted applications code, hosted application design documentation, published web services design documentation or ColdFusion baseline documentation.

If web services are not published, this finding is not applicable.

If web services are published, but the SOAP protocol is not used,  this finding is not applicable.

If web services are published and the SOAP protocol is used to access data, but the data is not sensitive,  this finding is not applicable.

Determine if  the ws-security suite is in place to provide secure authentication to the sensitive data by interviewing the administrator or by reviewing hosted applications code, hosted application design documentation, published web services design documentation or ColdFusion baseline documentation.

If web services are published using the SOAP protocol to access sensitive data and the ws-security suite is not used to secure the access, this is a finding.'
  desc 'fix', 'If web services are not published, this finding is not applicable.

If web services are published, but the SOAP protocol is not used,  this finding is not applicable.

If web services are published and the SOAP protocol is used to access data, but the data is not sensitive,  this finding is not applicable.

Install the ws-security suite to secure access to sensitive data.'
  impact 0.5
  ref 'DPMS Target Adobe ColdFusion 11'
  tag check_id: 'C-40409r641663_chk'
  tag severity: 'medium'
  tag gid: 'V-237190'
  tag rid: 'SV-237190r641665_rule'
  tag stig_id: 'CF11-04-000129'
  tag gtitle: 'SRG-APP-000156-AS-000106'
  tag fix_id: 'F-40372r641664_fix'
  tag 'documentable'
  tag legacy: ['SV-76943', 'V-62453']
  tag cci: ['CCI-001941']
  tag nist: ['IA-2 (8)']
end
