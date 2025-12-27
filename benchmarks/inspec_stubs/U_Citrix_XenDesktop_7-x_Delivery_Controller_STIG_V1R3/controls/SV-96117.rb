control 'SV-96117' do
  title 'Delivery Controller must limit the number of concurrent sessions to an organization-defined number for all accounts and/or account types.'
  desc 'Application management includes the ability to control the number of users and user sessions that utilize an application. Limiting the number of allowed users and sessions per user is helpful in limiting risks related to Denial-of-Service (DoS) attacks.

This requirement may be met via the application or by using information system session control provided by a web server with specialized session management capabilities. If it has been specified that this requirement will be handled by the application, the capability to limit the maximum number of concurrent single user sessions must be designed and built into the application. 

This requirement addresses concurrent sessions for information system accounts and does not address concurrent sessions by single users via multiple system accounts. The maximum number of concurrent sessions should be defined based on mission needs and the operational environment for each system.'
  desc 'check', 'Open Citrix Studio, right-click a Delivery Group, and choose "Edit Delivery Group". 

Verify the following check box is not checked: "Give access to unauthenticated (anonymous) users; no credentials are required to access StoreFront". 

If the check box is checked, this is a finding.

A Citrix Studio administrator account is needed to perform this check. Performing this check does not impact system reliability or availability.'
  desc 'fix', 'Open Citrix Studio, right-click a Delivery Group, and choose "Edit Delivery Group". 

Uncheck the following check box: "Give access to unauthenticated (anonymous) users; no credentials are required to access StoreFront". 

A Citrix Studio administrator account is needed to perform above fix.'
  impact 0.5
  ref 'DPMS Target XenDesktop 7.x Delivery Controller'
  tag check_id: 'C-81133r1_chk'
  tag severity: 'medium'
  tag gid: 'V-81403'
  tag rid: 'SV-96117r1_rule'
  tag stig_id: 'CXEN-DC-000005'
  tag gtitle: 'SRG-APP-000001'
  tag fix_id: 'F-88209r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000054']
  tag nist: ['AC-10']
end
