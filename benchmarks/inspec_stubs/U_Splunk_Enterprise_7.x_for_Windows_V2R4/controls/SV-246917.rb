control 'SV-246917' do
  title 'The System Administrator (SA) and Information System Security Officer (ISSO) must configure the retention of the log records based on the defined security plan.'
  desc 'If authorized individuals do not have the ability to modify auditing parameters in response to a changing threat environment, the organization may not be able to respond effectively and important forensic information may be lost.

The organization must define and document log retention requirements for each device and host and then configure Splunk Enterprise to comply with the required retention period.

This requirement enables organizations to extend or limit auditing as necessary to meet organizational requirements. Auditing that is limited to conserve information system resources may be extended to address certain threat situations.'
  desc 'check', 'Examine the site documentation for the retention time for log data.

Examine the following file in the Splunk installation folder:

(Note that these files may exist in one of the following folders or its subfolders:
$SPLUNK_HOME/etc/apps/
$SPLUNK_HOME/etc/slave-apps/)

$SPLUNK_HOME/etc/system/local/indexes.conf

For each index defined in the scope, the frozenTimePeriodInSecs setting must match the site documentation.

If the settings do not match, this is a finding.'
  desc 'fix', 'Edit the following file in the Splunk installation folder:

(Note that these files may exist in one of the following folders or its subfolders:
$SPLUNK_HOME/etc/apps/
$SPLUNK_HOME/etc/slave-apps/)

$SPLUNK_HOME/etc/system/local/indexes.conf

Set frozenTimePeriodInSecs to the defined retention period for each index location.'
  impact 0.3
  ref 'DPMS Target Splunk Enterprise 7.x for Windows'
  tag check_id: 'C-50349r768744_chk'
  tag severity: 'low'
  tag gid: 'V-246917'
  tag rid: 'SV-246917r879563_rule'
  tag stig_id: 'SPLK-CL-000260'
  tag gtitle: 'SRG-APP-000095-AU-000050'
  tag fix_id: 'F-50303r768745_fix'
  tag 'documentable'
  tag legacy: ['SV-111335', 'V-102391']
  tag cci: ['CCI-001914']
  tag nist: ['AU-12 (3)']
end
