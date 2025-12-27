control 'SV-242597' do
  title 'The Cisco ISE must generate a critical alert to be sent to the ISSO and SA (at a minimum) if it is unable to communicate with the central event log. This is required for compliance with C2C Step 1.'
  desc 'It is critical for the appropriate personnel to be aware if a system is at risk of failing to process audit logs as required. Without this notification, the security personnel may be unaware of an impending failure of the audit capability and system operation may be adversely affected.

Audit processing failures include software/hardware errors, failures in the audit capturing mechanisms, and audit storage capacity being reached or exceeded.

This requirement applies to each audit data storage repository (i.e., distinct information system component where log records are stored), the centralized audit storage capacity of organizations (i.e., all audit data storage repositories combined), or both.'
  desc 'check', 'If DoD is not at C2C Step 1 or higher, this is not a finding.

Verify that a log will be generated and sent when a Logging Target becomes unavailable.

From the Web Admin portal:
1. Choose Administration >> System >> Logging >> Logging Categories.
2. Verify that Internal Operations Diagnostics has "LogCollector" and "LogCollector2" set.

If there are a minimum of two logging targets selected for Internal Operations Diagnostics, this is not a finding.'
  desc 'fix', 'Configure a log to be generated and sent when a Logging Target becomes unavailable.

From the Web Admin portal:
1. Choose Administration >> System >> Logging >> Logging Categories.
2. Configure the "Internal Operations Diagnostics" category Targets field to have "LogCollector" and "LogCollector2". If the environment has an additional SYSLOG server, it can be selected here as well.

Note: "LogCollector" and "LogCollector2" are not configured for this category by default. These logs will be viewable at Operations >> Reports >> Reports >> Diagnostics >> System Diagnostic.'
  impact 0.5
  ref 'DPMS Target Cisco ISE NAC'
  tag check_id: 'C-45872r812775_chk'
  tag severity: 'medium'
  tag gid: 'V-242597'
  tag rid: 'SV-242597r812776_rule'
  tag stig_id: 'CSCO-NC-000230'
  tag gtitle: 'SRG-NET-000088-NAC-000440'
  tag fix_id: 'F-45829r714100_fix'
  tag 'documentable'
  tag cci: ['CCI-000139']
  tag nist: ['AU-5 a']
end
