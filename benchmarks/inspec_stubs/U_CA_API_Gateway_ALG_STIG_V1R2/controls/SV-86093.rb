control 'SV-86093' do
  title 'The CA API Gateway providing user access control intermediary services must generate audit records when successful/unsuccessful logon attempts occur.'
  desc 'Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

Audit records can be generated from various components within the information system (e.g., module or policy filter).

This requirement applies to the ALG traffic management functions, such as content filtering or intermediary services. This does not apply to audit logs generated on behalf of the device (device management).

The CA API Gateway by default audits when unsuccessful attempts to log on to a Registered Service or the Gateway occur. To enable the auditing of successful events, the log level on the Gateway must be increased to INFO, as by default it is set to WARNING, which only audits events that may be considered an issue.'
  desc 'check', 'Open the CA API Gateway - Policy Manager. 

Locate the Global Policy created for "message-received".

Open the policy and verify the "Audit Messages in Policy" Assertion has been added. 

If the Global policy does not exist or the "Audit Messages in Policy" Assertion is not present, this is a finding.'
  desc 'fix', 'Open the CA API Gateway - Policy Manager. 

If a Global Policy is not set for the system, create one by selecting "Tasks" from the main menu and choosing "Create Policy". 

Give the policy a name and select "Global Policy Fragment" from the Policy Type drop-down menu. 

Select "message-received" from the Policy Tag drop-down menu and click "OK". 

Locate the Global Policy created for "message-received". Open the policy and add the "Audit Messages in Policy" Assertion. Set the Level to "WARNING" to verify the normally successful logons are recorded as WARNINGS and not INFO.'
  impact 0.5
  ref 'DPMS Target CA API Gateway ALG'
  tag check_id: 'C-71859r1_chk'
  tag severity: 'medium'
  tag gid: 'V-71469'
  tag rid: 'SV-86093r1_rule'
  tag stig_id: 'CAGW-GW-000860'
  tag gtitle: 'SRG-NET-000503-ALG-000038'
  tag fix_id: 'F-77789r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
