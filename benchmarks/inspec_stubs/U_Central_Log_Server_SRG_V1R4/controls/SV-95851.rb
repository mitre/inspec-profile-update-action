control 'SV-95851' do
  title 'The System Administrator (SA) and Information System Security Manager (ISSM) must configure the retention of the log records based on criticality level, event type, and/or retention period, at a minimum.'
  desc 'If authorized individuals do not have the ability to modify auditing parameters in response to a changing threat environment, the organization may not be able to respond effectively and important forensic information may be lost.

The organization must define and document log retention requirements for each device and host and then configure the Central Log Sever to comply with the required retention period.

This requirement enables organizations to extend or limit auditing as necessary to meet organizational requirements. Auditing that is limited to conserve information system resources may be extended to address certain threat situations. In addition, auditing may be limited to a specific set of events to facilitate audit reduction, analysis, and reporting. Organizations can establish time thresholds in which audit actions are changed; for example, in near real time, within minutes, or within hours.'
  desc 'check', 'Examine the configuration.

Verify the SA and ISSM have been assigned the privileges needed to allow these roles to change the level and type of log records that are retained in the centralized repository based on any selectable event criteria. 

Verify the retention configuration for each host and device is in compliance with the documented organization criteria, including the identified criticality level, event type, and/or retention period.

If the Central Log Server is not configured to allow the SA and ISSM to change the retention of the log records, this is a finding.

If the retention is not in compliance with the organization’s documentation, this is a finding.'
  desc 'fix', 'Configure the Central Log Server with the privileges needed to allow the SA and ISSM to change the level and type of log records that are retained in the centralized repository based on any selectable event criteria.

Based on the documented requirements for each application, configure the events server to retain log records based on criticality level, type of event, and/or retention period, at a minimum.'
  impact 0.3
  ref 'DPMS Target SRG-APP-LOG'
  tag check_id: 'C-80795r1_chk'
  tag severity: 'low'
  tag gid: 'V-81137'
  tag rid: 'SV-95851r1_rule'
  tag stig_id: 'SRG-APP-000353-AU-000050'
  tag gtitle: 'SRG-APP-000353-AU-000050'
  tag fix_id: 'F-87911r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001914']
  tag nist: ['AU-12 (3)']
end
