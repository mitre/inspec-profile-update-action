control 'SV-79653' do
  title 'The DataPower Gateway must require users to re-authenticate when privilege escalation or role changes occur.'
  desc 'Without re-authentication, users may access resources or perform tasks for which they do not have authorization.

When devices provide the capability to change security roles, it is critical the user re-authenticate.

In addition to the re-authentication requirements associated with session locks, organizations may require re-authentication of individuals and/or devices in other situations, including (but not limited to) the following circumstances.

(i) When authenticators change;
(ii) When roles change;
(iii) When security categories of information systems change;
(iv) When the execution of privileged functions occurs;
(v) After a fixed period of time; or
(vi) Periodically.

Within the DoD, the minimum circumstances requiring re-authentication are privilege escalation and role changes.'
  desc 'check', 'Go to Status >> Main >> Active Users and ensure that the user is not currently logged on. If the user is logged in, it is a finding.'
  desc 'fix', "After making any account privilege changes, administrator must go to Status >> Main >> Active Users and disconnect the user's current session if they are currently logged on."
  impact 0.5
  ref 'DPMS Target IBM DataPower XI52 NDM'
  tag check_id: 'C-65791r1_chk'
  tag severity: 'medium'
  tag gid: 'V-65163'
  tag rid: 'SV-79653r1_rule'
  tag stig_id: 'WSDP-NM-000108'
  tag gtitle: 'SRG-APP-000389-NDM-000306'
  tag fix_id: 'F-71103r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002038']
  tag nist: ['IA-11']
end
