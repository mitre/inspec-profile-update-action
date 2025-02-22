control 'SV-85957' do
  title 'The CA API Gateway must produce audit records containing information to establish the outcome of the events.'
  desc 'Without information about the outcome of events, security personnel cannot make an accurate assessment as to whether an attack was successful or if changes were made to the security state of the network.

Event outcomes can include indicators of event success or failure and event-specific results (e.g., the security state of the network after the event occurred). They also provide a means to measure the impact of an event and help authorized personnel to determine the appropriate response.

The CA API Gateway policies must be configured to provide the required level of auditing in accordance with organizational requirements.'
  desc 'check', 'Open the CA API Gateway - Policy Manager. 

Select "Gateway Audit Events" from the "View" menu. 

Execute a logon failure of one of the Registered Services using an approved testing tool or an application that accesses the service. 

View the audit logs to notice the logging of the authentication failure showing the outcome of the logon failure event. 

If the outcome of the event is not shown, this is a finding.'
  desc 'fix', 'If a logon failure is not recorded, check the Registered Service for the existence of an authentication mechanism using an Access Control Assertion such as "Authenticate Against Identity Provider".

Also verify that a Credential Source is added from the Access Control Assertions, such as "Require HTTP Basic Credentials" or "Require WS -Security Username Token Profile Credentials".

Other outcomes of events occurring on a Registered Service, such as SQL Injection or PHP Evaluation Injections, will be automatically logged when the Assertion checking for the attack is added to a Registered Service or set in Global Policy. The event will include the outcome displaying its results.'
  impact 0.5
  ref 'DPMS Target CA API Gateway ALG'
  tag check_id: 'C-71733r1_chk'
  tag severity: 'medium'
  tag gid: 'V-71333'
  tag rid: 'SV-85957r1_rule'
  tag stig_id: 'CAGW-GW-000220'
  tag gtitle: 'SRG-NET-000078-ALG-000047'
  tag fix_id: 'F-77641r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000134']
  tag nist: ['AU-3 e']
end
