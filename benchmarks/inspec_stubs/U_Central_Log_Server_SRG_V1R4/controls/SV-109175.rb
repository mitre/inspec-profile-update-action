control 'SV-109175' do
  title 'The Central Log Server must require users to reauthenticate when organization-defined circumstances or situations require reauthentication.'
  desc 'Without reauthentication, users may access resources or perform tasks for which they do not have authorization. 

When applications provide the capability to change security roles or escalate the functional capability of the application, it is critical the user reauthenticate.

In addition to the reauthentication requirements associated with session locks, organizations may require reauthentication of individuals and/or devices in other situations, including (but not limited to) the following circumstances.

(i) When authenticators change; 
(ii) When roles change; 
(iii) When security categories of information systems change; 
(iv) When the execution of privileged functions occurs; 
(v) After a fixed period of time; or
(vi) Periodically.

Within the DoD, the minimum circumstances requiring reauthentication are privilege escalation and role changes.'
  desc 'check', 'Examine the configuration.

Verify the Central Log Server requires users to reauthenticate when situations require reauthentication.

If the Central Log Server is not configured to reauthenticate when necessary, this is a finding.'
  desc 'fix', 'Configure the Central Log Server to reauthenticate users when situations require reauthentication.'
  impact 0.3
  ref 'DPMS Target SRG-APP-LOG'
  tag check_id: 'C-98923r1_chk'
  tag severity: 'low'
  tag gid: 'V-100071'
  tag rid: 'SV-109175r1_rule'
  tag stig_id: 'SRG-APP-000389-AU-000180'
  tag gtitle: 'SRG-APP-000389-AU-000180'
  tag fix_id: 'F-105757r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002038']
  tag nist: ['IA-11']
end
