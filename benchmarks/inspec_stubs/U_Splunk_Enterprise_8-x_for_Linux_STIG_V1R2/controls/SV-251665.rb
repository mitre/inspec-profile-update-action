control 'SV-251665' do
  title 'The System Administrator (SA) and Information System Security Manager (ISSM) must configure the retention of the log records based on the defined security plan.'
  desc 'If authorized individuals do not have the ability to modify auditing parameters in response to a changing threat environment, the organization may not be able to respond effectively and important forensic information may be lost.

The organization must define and document log retention requirements for each device and host and then configure Splunk Enterprise to comply with the required retention period.

This requirement enables organizations to extend or limit auditing as necessary to meet organizational requirements. Auditing that is limited to conserve information system resources may be extended to address certain threat situations.'
  desc 'check', 'This check is applicable to the instance with the Indexer role, which may be a different instance in a distributed environment.

Examine the site documentation for the retention time for log data.

Examine the following file in the Splunk installation folder:

$SPLUNK_HOME/etc/system/local/indexes.conf

For each index defined in the scope, the frozenTimePeriodInSecs setting should match the site documentation.

If the settings do not match, this is a finding.'
  desc 'fix', 'Edit the following file in the Splunk installation folder:

$SPLUNK_HOME/etc/system/local/indexes.conf

Set frozenTimePeriodInSecs to the defined retention period for each index location.'
  impact 0.3
  ref 'DPMS Target Splunk Enterprise 8.x for Linux'
  tag check_id: 'C-55103r819089_chk'
  tag severity: 'low'
  tag gid: 'V-251665'
  tag rid: 'SV-251665r819091_rule'
  tag stig_id: 'SPLK-CL-000120'
  tag gtitle: 'SRG-APP-000095-AU-000050'
  tag fix_id: 'F-55057r819090_fix'
  tag 'documentable'
  tag cci: ['CCI-001914']
  tag nist: ['AU-12 (3)']
end
