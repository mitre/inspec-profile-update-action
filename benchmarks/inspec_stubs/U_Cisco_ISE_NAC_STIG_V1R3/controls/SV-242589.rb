control 'SV-242589' do
  title 'The Cisco ISE must generate a log record when an endpoint fails authentication. This is This is required for compliance with C2C Step 1.'
  desc 'Failing the Cisco ISE assessment means that an unauthorized machine has attempted to access the secure network. Without generating log records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.'
  desc 'check', 'If DoD is not at C2C Step 1 or higher, this is not a finding.
If not required by the NAC SSP, this is not a finding.

Verify that a log will be generated and sent when an Endpoint has a change in posture status.

From the Web Admin portal:
1. Choose Administration >> System >> Logging >> Logging Categories.
2. Verify the Failed Attempts has LogCollector set as a target at a minimum.

If the Failed Attempts logging category is not configured to send to the LogCollector and/or another logging target, this is a finding.'
  desc 'fix', 'If required by the NAC SSP, configure a log to be generated and sent when an endpoint has a change in posture status.

From the Web Admin portal:
1. Choose Administration >> System >> Logging >> Logging Categories.
2. Configure the "Failed Attempts" category and the Targets field to have LogCollector selected at a minimum. This is the default setting. If the environment has an additional SYSLOG server, it can be selected here as well.'
  impact 0.5
  ref 'DPMS Target Cisco ISE NAC'
  tag check_id: 'C-45864r812759_chk'
  tag severity: 'medium'
  tag gid: 'V-242589'
  tag rid: 'SV-242589r812760_rule'
  tag stig_id: 'CSCO-NC-000150'
  tag gtitle: 'SRG-NET-000492-NAC-002100'
  tag fix_id: 'F-45821r803553_fix'
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
