control 'SV-242591' do
  title 'The Cisco ISE must send an alert to the system administrator, at a minimum, when endpoints fail the policy assessment checks for organization-defined infractions.'
  desc 'Failing the Cisco ISE assessment, means that an unauthorized machine has attempted to access the secure network. Without generating log records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident, or identify those responsible for one.

Log records can be generated from various components within the information system (e.g., module or policy filter).'
  desc 'check', 'Verify that an alarm will be generated and sent when an Endpoint has a change in posture status.

From the Web Admin portal:
1. Choose Administration >> System >> Logging >> Logging Categories.
2. Verify the Posture and Client Provisioning Audit has LogCollector set as a target at a minimum.

If the Posture and Client Provisioning Audit logging category is not configured to send to the LogCollector and/or another logging target, this is a finding.'
  desc 'fix', 'Configure an alarm to be generated and sent when an Endpoint has a change in posture status.

From the Web Admin portal:
1. Choose Administration >> System >> Logging >> Logging Categories.
2. Configure the "Posture and Client Provisioning Audit" category and the Targets field needs to have LogCollector selected at a minimum (This is the default setting). If the environment has an additional SYSLOG server, it can be selected here as well.'
  impact 0.5
  ref 'DPMS Target Cisco ISE NAC'
  tag check_id: 'C-45866r714081_chk'
  tag severity: 'medium'
  tag gid: 'V-242591'
  tag rid: 'SV-242591r714083_rule'
  tag stig_id: 'CSCO-NC-000170'
  tag gtitle: 'SRG-NET-000492-NAC-002120'
  tag fix_id: 'F-45823r714082_fix'
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
