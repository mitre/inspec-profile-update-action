control 'SV-86067' do
  title 'The CA API Gateway providing content filtering must protect against known and unknown types of Denial of Service (DoS) attacks by employing rate-based attack prevention behavior analysis.'
  desc 'If the network does not provide safeguards against DoS attacks, network resources will be unavailable to users.

Installation of content filtering gateways and application layer firewalls at key boundaries in the architecture mitigates the risk of DoS attacks. These attacks can be detected by matching observed communications traffic with patterns of known attacks and monitoring for anomalies in traffic volume/type.

Detection components that use rate-based behavior analysis can detect attacks when signatures for the attack do not exist or are not installed. These attacks include zero-day attacks, which are new attacks for which vendors have not yet developed signatures. Rate-based behavior analysis can detect sophisticated, Distributed DoS (DDoS) attacks by correlating traffic information from multiple network segments or components.
 
This requirement applies to the communications traffic functionality of the ALG as it pertains to handling communications traffic, rather than to the ALG device itself.

The CA API Gateway must enable a rate limit in an effort to provide safeguards against DoS attacks.'
  desc 'check', %q(Open the CA API Gateway - Policy Manager. 

Check the lower-left corner of the CA API Gateway - Policy Manager to see if a Global Policy is set that includes an "Apply Rate Limit" Assertion. (Global policies are displayed with a green icon beside their name.) 

If the policy does not exist, this is a finding. 

If it does exist, verify the Rate Limits are set to meet the organization's security requirements for DoS Attacks.

If the Rate Limits are not set to meet the organization's security requirements for DoS attacks, this is a finding.)
  desc 'fix', %q(Open the CA API Gateway - Policy Manager. 

Select "Tasks" from the main menu and choose "Create Policy". 

Give the policy a name and select "Global Policy Fragment" from the Policy Type drop-down menu. 

Select "message-received" from the Policy Tag drop-down menu and click "OK".

Drag the "Apply Rate Limit" Assertion into the newly created Global Policy Fragment. 

Set the "Maximum requests per second" and/or "Maximum concurrent requests" and/or "Limit each:" values to meet the organization's requirements to protect against DoS attacks. 

Click "Save and Activate".)
  impact 0.5
  ref 'DPMS Target CA API Gateway ALG'
  tag check_id: 'C-71833r1_chk'
  tag severity: 'medium'
  tag gid: 'V-71443'
  tag rid: 'SV-86067r1_rule'
  tag stig_id: 'CAGW-GW-000670'
  tag gtitle: 'SRG-NET-000362-ALG-000112'
  tag fix_id: 'F-77761r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
