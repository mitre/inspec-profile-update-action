control 'SV-221937' do
  title 'Splunk Enterprise idle session timeout must be set to not exceed 15 minutes.'
  desc 'Without reauthentication, users may access resources or perform tasks for which they do not have authorization.

When applications provide the capability to change security roles or escalate the functional capability of the application, it is critical the user reauthenticate.

In addition to the reauthentication requirements associated with session locks, organizations may require reauthentication of individuals and/or devices in other situations, including (but not limited to) the following circumstances:

(i) When authenticators change;
(ii) When roles change;
(iii) When security categories of information systems change;
(iv) When the execution of privileged functions occurs;
(v) After a fixed period of time; or
(vi) Periodically.

Within the DoD, the minimum circumstances requiring reauthentication are privilege escalation and role changes.'
  desc 'check', 'Select Settings >> Server Settings >> General Settings and verify that Session timeout is set to 15 minutes or less.

If Splunk is not configured to 15 minutes or less, this is a finding.'
  desc 'fix', 'Select Settings >> Server Settings >> General Settings and set Session timeout to 15 minutes or less.'
  impact 0.3
  ref 'DPMS Target Splunk Enterprise 7.x for Windows'
  tag check_id: 'C-23651r420279_chk'
  tag severity: 'low'
  tag gid: 'V-221937'
  tag rid: 'SV-221937r879762_rule'
  tag stig_id: 'SPLK-CL-000180'
  tag gtitle: 'SRG-APP-000389-AU-000180'
  tag fix_id: 'F-23640r420280_fix'
  tag 'documentable'
  tag legacy: ['SV-111365', 'V-102421']
  tag cci: ['CCI-002038']
  tag nist: ['IA-11']
end
