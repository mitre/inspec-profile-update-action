control 'SV-85919' do
  title 'The CA API Gateway providing user access control intermediary services must limit users to two concurrent sessions.'
  desc 'Network element management includes the ability to control the number of users and user sessions that utilize a network element. Limiting the number of current sessions per user is helpful in limiting risks related to Denial of Service (DoS) attacks.

This requirement addresses concurrent sessions for information system accounts and does not address concurrent sessions by single users via multiple system accounts. The maximum number of concurrent sessions must be the same as the requirements specified for the application for which it serves as intermediary.

The CA API Gateway must have Global Policies that enable rate limits that throttle the number of concurrent sessions for Registered Services/APIs in accordance with organizational requirements.'
  desc 'check', "Log on to the CA API Gateway - Policy Manager. 

By default, the Gateway has no limit set on the number of concurrent sessions. However, this is configurable in Global Policy. 

Check the lower-left corner of the CA API Gateway - Policy Manager to see if a Global Policy for concurrent sessions has been previously configured by an administrator. (Global policies are displayed with a green icon beside their name.) 

If the policy does not exist, this is a finding. 

If the policy does exist, verify the Rate Limits are set to meet the organization's security requirements.

If the Rate Limits are not set to meet the organization's security requirements, this is a finding."
  desc 'fix', %q(Open the CA API Gateway - Policy Manager. 

Select "Tasks" from the main menu and choose "Create Policy". Give the policy a name and select "Global Policy Fragment" from the Policy Type drop-down menu. 

Select "message-received" from the Policy Tag drop-down menu and click "OK".

Drag the "Apply Rate Limit" Assertion into the newly created Global Policy Fragment. Set the "Maximum requests per second" and/or "Maximum concurrent requests" and/or "Limit each:" values to meet the organization's requirements. 

Click "Save and Activate".)
  impact 0.5
  ref 'DPMS Target CA API Gateway ALG'
  tag check_id: 'C-71691r1_chk'
  tag severity: 'medium'
  tag gid: 'V-71295'
  tag rid: 'SV-85919r1_rule'
  tag stig_id: 'CAGW-GW-000160'
  tag gtitle: 'SRG-NET-000053-ALG-000001'
  tag fix_id: 'F-77605r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000054']
  tag nist: ['AC-10']
end
