control 'SV-234532' do
  title 'The UEM server must require users (administrators) to reauthenticate when roles change.'
  desc 'Without reauthentication, users may access resources or perform tasks for which they do not have authorization. 

When applications provide the capability to change security roles or escalate the functional capability of the application, it is critical the user reauthenticate.

In addition to the reauthentication requirements associated with session locks, organizations may require reauthentication of individuals and/or devices in other situations, including (but not limited to) the following circumstances.

(i) When authenticators change; 
(ii) When roles change; 
(iii) When security categories of information systems change; 
(iv) When the execution of privileged functions occurs; 
(v) After a fixed period of time; or
(vi) Periodically.

Within the DoD, the minimum circumstances requiring reauthentication are privilege escalation and role changes. 

Satisfies:FMT_SMF.1.1(2) b 
Reference:PP-MDM-431016'
  desc 'check', 'Verify the UEM server requires users (administrators) to reauthenticate when roles change.

If the UEM server does not require users (administrators) to reauthenticate when roles change, this is a finding.'
  desc 'fix', 'Configure the UEM server to require users (administrators) to reauthenticate when roles change.'
  impact 0.5
  ref 'DPMS Target Unified Endpoint Management Server'
  tag check_id: 'C-37717r615239_chk'
  tag severity: 'medium'
  tag gid: 'V-234532'
  tag rid: 'SV-234532r617355_rule'
  tag stig_id: 'SRG-APP-000389-UEM-000260'
  tag gtitle: 'SRG-APP-000389'
  tag fix_id: 'F-37682r615240_fix'
  tag 'documentable'
  tag cci: ['CCI-002038']
  tag nist: ['IA-11']
end
