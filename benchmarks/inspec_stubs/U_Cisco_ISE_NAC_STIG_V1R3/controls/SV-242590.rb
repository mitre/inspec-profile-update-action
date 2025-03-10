control 'SV-242590' do
  title 'The Cisco ISE must generate a log record when the client machine fails posture assessment because required security software is missing or has been deleted. This is This is required for compliance with C2C Step 1.'
  desc 'Failing the Cisco ISE assessment means an unauthorized machine has attempted to access the secure network. Without generating log records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident, or identify those responsible for one.

Log records can be generated from various components within the information system (e.g., module or policy filter).'
  desc 'check', 'If DoD is not at C2C Step 1 or higher, this is not a finding.
If not required by the NAC SSP, this is not a finding.

Verify that a log will be generated and sent when an Endpoint has a change in posture status.

From the Web Admin portal:
1. Choose Administration >> System >> Logging >> Logging Categories.
2. Verify the Posture and Client Provisioning Audit has LogCollector set as a target at a minimum.

If the Posture and Client Provisioning Audit logging category is not configured to send to the LogCollector and/or another logging target, this is a finding.'
  desc 'fix', 'If required by the NAC SSP, configure a log to be generated and sent when an endpoint has a change in posture status.

From the Web Admin portal:
1. Choose Administration >> System >> Logging >> Logging Categories.
2. Configure the "Posture and Client Provisioning Audit" category and the Targets field to have LogCollector selected at a minimum. This is the default setting. If the environment has an additional SYSLOG server, it can be selected here as well.'
  impact 0.5
  ref 'DPMS Target Cisco ISE NAC'
  tag check_id: 'C-45865r812761_chk'
  tag severity: 'medium'
  tag gid: 'V-242590'
  tag rid: 'SV-242590r812762_rule'
  tag stig_id: 'CSCO-NC-000160'
  tag gtitle: 'SRG-NET-000492-NAC-002101'
  tag fix_id: 'F-45822r803556_fix'
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
