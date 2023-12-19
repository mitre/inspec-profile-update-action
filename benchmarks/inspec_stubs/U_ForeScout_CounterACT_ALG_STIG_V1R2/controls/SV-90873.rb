control 'SV-90873' do
  title 'CounterACT, when providing user authentication intermediary services, must require users to reauthenticate when organization-defined circumstances or situations require reauthentication.'
  desc 'Without reauthentication, users may access resources or perform tasks for which they do not have authorization.

In addition to the reauthentication requirements associated with session locks, organizations may require reauthentication of individuals and/or devices in other situations, including (but not limited to) the following circumstances: 

1. When authenticators change
2. When roles change
3. When security categories of information systems change
4. When the execution of privileged functions occurs
5. After a fixed period of time
6. Periodically

Within the DoD, the minimum circumstances requiring reauthentication are privilege escalation and role changes.

This requirement only applies to components where this is specific to the function of the device or has the concept of user authentication (e.g., VPN or ALG capability). This does not apply to authentication for the purpose of configuring the device itself (i.e., device management).'
  desc 'check', 'If CounterACT does not provide user authentication intermediary services, this is not applicable.

Verify CounterACT is configured to require users to reauthenticate when organization-defined circumstances or situations require reauthentication. 

1. Connect to CounterACT’s Admin Console and log in.
2. Go to Tools >> Options >> 802.1x.
3. Select the Pre-Admission Authorization tab.
4. On each Rule that "Accepts", verify there is an Attribute "Session-Timeout" configured to the maximum session configuration, typically 60 minutes, but not more than 120. 

If CounterACT does not require users to reauthenticate when organization-defined circumstances or situations require reauthentication, this is a finding.'
  desc 'fix', 'If user access control intermediary services are provided, configure CounterACT to require users to reauthenticate when organization-defined circumstances or situations require reauthentication.

1. Connect to CounterACT’s Admin Console and log in.
2. Go to Tools >> Options >> 802.1x.
3. Select the Pre-Admission Authorization tab.
4. On each Rule that "Accepts", ensure there is an Attribute "Session-Timeout" configured to the maximum session configuration, typically 60 minutes, but not more than 120.'
  impact 0.5
  ref 'DPMS Target ForeScout CounterACT ALG'
  tag check_id: 'C-75871r1_chk'
  tag severity: 'medium'
  tag gid: 'V-76185'
  tag rid: 'SV-90873r1_rule'
  tag stig_id: 'CACT-AG-000011'
  tag gtitle: 'SRG-NET-000337-ALG-000096'
  tag fix_id: 'F-82823r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002038']
  tag nist: ['IA-11']
end
