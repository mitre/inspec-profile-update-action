control 'SV-205568' do
  title 'The Mainframe Product must require users to reauthenticate when circumstances or situations require reauthentication as defined in site security plan.'
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
  desc 'check', 'If the Mainframe Product has no function or capability for user logon, this is not applicable.

If the Mainframe Product employs an external security manager for all account management functions, this is not applicable.

Examine user account management configurations.

If the Mainframe Product is configured to require user reauthentication when circumstances or situations require reauthentication as defined in site security plan, this is not a finding.'
  desc 'fix', 'Configure the Mainframe Product to require user reauthentication when circumstances or situations require reauthentication as defined in site security plan.'
  impact 0.5
  ref 'DPMS Target Mainframe Product'
  tag check_id: 'C-5834r299931_chk'
  tag severity: 'medium'
  tag gid: 'V-205568'
  tag rid: 'SV-205568r851334_rule'
  tag stig_id: 'SRG-APP-000389-MFP-000204'
  tag gtitle: 'SRG-APP-000389'
  tag fix_id: 'F-5834r299932_fix'
  tag 'documentable'
  tag legacy: ['SV-82817', 'V-68327']
  tag cci: ['CCI-002038']
  tag nist: ['IA-11']
end
