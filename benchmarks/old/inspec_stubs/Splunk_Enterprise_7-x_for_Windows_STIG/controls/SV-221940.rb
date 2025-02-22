control 'SV-221940' do
  title 'Splunk Enterprise must notify analysts of applicable events for Tier 2 CSSP and JRSS only.'
  desc 'Sending notifications or populating dashboards are ways to monitor and alert on applicable events and allow analysts to mitigate issues.

Tier 2 CSSP and JRSS analysts perform higher-level analysis at larger network coverage and have specific guidelines to handle alerts and reports. This requirement allows these analysts to not be burdened by all of the lower-level alerts that can be considered "white noise" by isolating their alerting and reporting requirements from other requirements in this STIG.

'
  desc 'check', 'This check applies to Tier 2 CSSP or JRSS instances only.

Verify that notifications and dashboards are configured in accordance with designated SSPs, SOPs, and/or TTPs.

The absence of notifications and dashboards is a finding.'
  desc 'fix', 'This fix applies to Tier 2 CSSP or JRSS instances only.

Configure Splunk notifications and dashboards in accordance with designated SSPs, SOPs, and/or TTPs.'
  impact 0.3
  ref 'DPMS Target Splunk Enterprise 7.x for Windows'
  tag check_id: 'C-23654r420288_chk'
  tag severity: 'low'
  tag gid: 'V-221940'
  tag rid: 'SV-221940r879669_rule'
  tag stig_id: 'SPLK-CL-000235'
  tag gtitle: 'SRG-APP-000291-AU-000200'
  tag fix_id: 'F-23643r420289_fix'
  tag satisfies: ['SRG-APP-000291-AU-000200', 'SRG-APP-000292-AU-000420', 'SRG-APP-000293-AU-000430', 'SRG-APP-000294-AU-000440']
  tag 'documentable'
  tag legacy: ['SV-111389', 'V-102385']
  tag cci: ['CCI-001683', 'CCI-001684', 'CCI-001685', 'CCI-001686']
  tag nist: ['AC-2 (4)', 'AC-2 (4)', 'AC-2 (4)', 'AC-2 (4)']
end
