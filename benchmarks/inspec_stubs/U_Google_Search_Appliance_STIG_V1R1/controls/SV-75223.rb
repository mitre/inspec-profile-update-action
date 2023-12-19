control 'SV-75223' do
  title 'The Google Search Appliance must be configured to prevent browsers from saving user credentials.'
  desc 'Web services are web applications providing a method of communication between two or more different electronic devices.  They are normally used by applications to provide each other with data.  

The W3C defines a web service as:
"a software system designed to support interoperable machine to machine interaction over a network. It has an interface described in a machine processable format (specifically Web Services Description Language or WSDL). Other systems interact with the web service in a manner prescribed by its description using SOAP messages typically conveyed using HTTP with an XML serialization in conjunction with other web-related standards".

Web services provide different challenges in managing access than what is presented by typical user based applications. In contrast to conventional access control approaches which employ static information system accounts and predefined sets of user privileges, many service-oriented architecture implementations rely on run time access control decisions facilitated by dynamic privilege management.  While user identities remain relatively constant over time, user privileges may change more frequently based on the ongoing mission/business requirements and operational needs of the organization. 

In contrast to conventional approaches to identification and authentication which employ static information system accounts for preregistered users, many service-oriented architecture implementations rely on establishing identities at run time for entities that were previously unknown. Dynamic establishment of identities and association of attributes and privileges with these identities are anticipated and provisioned. Pre-established trust relationships and mechanisms with appropriate authorities to validate identities and related credentials are essential.'
  desc 'check', 'Open the GSA Web Admin Console at https:<your GSA IP or hostname>:8443.

Login to the GSA management interface.
  
Navigate to "Administration", select "User Accounts".

Under "Other Settings" - If "Prevent browsers from saving user credentials on the Admin Console and Version Manager login pages" is checked, this is not a finding.'
  desc 'fix', 'Open the GSA Web Admin Console at https:<your GSA IP or hostname>:8443.

Login to the GSA management interface.
  
Navigate to "Administration", select "User Accounts".

Under "Other Settings" - Enable option "Prevent browsers from saving user credentials on the Admin Console and Version Manager login pages".

Click Save.'
  impact 0.7
  ref 'DPMS Target Google Search Appliance v3.1'
  tag check_id: 'C-61693r1_chk'
  tag severity: 'high'
  tag gid: 'V-60771'
  tag rid: 'SV-75223r1_rule'
  tag stig_id: 'GSAP-00-000515'
  tag gtitle: 'SRG-APP-000162'
  tag fix_id: 'F-66451r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-000802']
  tag nist: ['CM-6 b', 'IA-4 (5)']
end
