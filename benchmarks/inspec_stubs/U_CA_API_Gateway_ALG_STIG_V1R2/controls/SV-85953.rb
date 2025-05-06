control 'SV-85953' do
  title 'The CA API Gateway must produce audit records containing information to establish the source of the events.'
  desc 'Without establishing the source of the event, it is impossible to establish, correlate, and investigate the events leading up to an outage or attack. In order to compile an accurate risk assessment and provide forensic analysis, security personnel need to know the source of the event.

In addition to logging where events occur within the network, the audit records must also identify sources of events such as IP addresses, processes, and node or device names.

The CA API Gateway policies must be configured to provide the required level of auditing in accordance with organizational requirements.'
  desc 'check', %q(Open the CA API Gateway - Policy Manager. 

Select "Gateway Audit Events" from the "View" menu. 

Execute a logon failure of one of the Registered Services using an approved testing tool or an Application that accesses the service. 

View the Audit logs to notice the logging of the Authentication failure as well as the source of the failure showing the individual client ID's IP address. 

If the failure is not logged or the source is not properly displayed, this is a finding.)
  desc 'fix', 'If a logon failure is not recorded, check the Registered Service for the existence of an Authentication Mechanism using an Access Control Assertion such as "Authenticate Against Identity Provider". 

Also verify a Credential Source is added from the Access Control Assertions, such as "Require HTTP Basic Credentials" or "Require WS-Security Username Token Profile Credentials".

Other attacks on a Registered Service, such as SQL Injection or PHP Evaluation Injections, will be automatically logged when the Assertion checking for the attack is added to a Registered Service or set in Global Policy. The event will include the source of the attack indicated by the client ID.'
  impact 0.5
  ref 'DPMS Target CA API Gateway ALG'
  tag check_id: 'C-71729r1_chk'
  tag severity: 'medium'
  tag gid: 'V-71329'
  tag rid: 'SV-85953r1_rule'
  tag stig_id: 'CAGW-GW-000210'
  tag gtitle: 'SRG-NET-000077-ALG-000046'
  tag fix_id: 'F-77639r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000133']
  tag nist: ['AU-3 d']
end
