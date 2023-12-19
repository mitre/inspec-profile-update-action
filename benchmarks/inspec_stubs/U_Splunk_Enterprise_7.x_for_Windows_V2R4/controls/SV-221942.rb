control 'SV-221942' do
  title 'Splunk Enterprise must be configured with a successful/unsuccessful logon attempts report.'
  desc 'The SIEM or Central Log Server is the mitigation method for most of the other STIGs applied to an organization. Robust alerting and reporting is a key feature in any incident response plan.

The ability to report on logon attempts is the first step is creating a chain of events for a forensic analysis and incident response.'
  desc 'check', 'If the Splunk instance is used for Tier 2 CSSP (formerly CND-SP) or JRSS analysis, this check is N/A.

Interview the System Administrator (SA) to demonstrate that a logon attempts report exists.

If a report does not exist, this is a finding.'
  desc 'fix', 'If the Splunk instance is used for Tier 2 CSSP (formerly CND-SP) or JRSS analysis, this fix is N/A.

Configure Splunk Enterprise using the reporting and notification tools to create a report that audits the logon attempts. Make this report available to the ISSM and other required individuals.'
  impact 0.5
  ref 'DPMS Target Splunk Enterprise 7.x for Windows'
  tag check_id: 'C-23656r420294_chk'
  tag severity: 'medium'
  tag gid: 'V-221942'
  tag rid: 'SV-221942r879874_rule'
  tag stig_id: 'SPLK-CL-000280'
  tag gtitle: 'SRG-APP-000503-AU-000280'
  tag fix_id: 'F-23645r420295_fix'
  tag 'documentable'
  tag legacy: ['SV-111339', 'V-102395']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
