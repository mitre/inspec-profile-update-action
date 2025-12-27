control 'SV-223239' do
  title 'SharePoint must maintain and support the use of security attributes with stored information.'
  desc 'Security attributes are abstractions representing the basic properties or characteristics of an entity (e.g., subjects and objects) with respect to safeguarding information.

These attributes are typically associated with internal data structures (e.g., records, buffers, files) within the information system and are used to enable the implementation of access control and flow control policies, reflect special dissemination, handling or distribution instructions, or support other aspects of the information security policy.

One example includes marking data as classified or FOUO. These security attributes may be assigned manually or during data processing, but, either way, it is imperative these assignments are maintained while the data is in storage. If the security attributes are lost when the data is stored, there is the risk of a data compromise.'
  desc 'check', 'Review the SharePoint server to ensure the use of security attributes with stored information is maintained.

Click Site Settings. 

Under the Web Designer Galleries menu, click Site Content Types. 

Define a set of Content Types that can hold "security attributes", e.g., FOUO, etc. 

For each required Content Type, under "Change Content Type Column" ensure "Required (Must contain information) is selected. Otherwise, this is a finding.'
  desc 'fix', 'Configure the SharePoint server to maintain and support the use of security attributes with stored information.

From the Site Collection Settings menu:
Add a column to Content Types that can hold "security attributes", e.g., FOUO, etc., and "prompt the user to enter as metadata or properties to collect when documents of this content type are added to SharePoint."'
  impact 0.5
  ref 'DPMS Target Microsoft SharePoint 2013'
  tag check_id: 'C-24912r430777_chk'
  tag severity: 'medium'
  tag gid: 'V-223239'
  tag rid: 'SV-223239r612235_rule'
  tag stig_id: 'SP13-00-000010'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-24900r430778_fix'
  tag 'documentable'
  tag legacy: ['SV-74365', 'V-59935']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
