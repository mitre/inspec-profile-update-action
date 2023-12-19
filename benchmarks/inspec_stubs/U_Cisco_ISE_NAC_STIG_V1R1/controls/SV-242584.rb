control 'SV-242584' do
  title 'The Cisco ISE must send an alert to the Information System Security Manager (ISSM) and System Administrator (SA), at a minimum, when security issues are found that put the network at risk.'
  desc "Trusted computing should require authentication and authorization of both the user's identity and the identity of the computing device. An authorized user may be accessing the network remotely from a computer that does not meet DoD standards. This may compromise user information, particularly before or after a VPN tunnel is established."
  desc 'check', 'Verify that an alarm will be generated and sent when an Endpoint has a change in posture status.

From the Web Admin portal:
1. Choose Administration >> System >> Logging >> Logging Categories.
2. Verify the "AAA Audit", "Failed Attempts", and "Posture and Client Provisioning Audit" have LogCollector set as a target at a minimum.

If the Posture and Client Provisioning Audit logging category is not configured to send to the LogCollector and/or another logging target, this is a finding.'
  desc 'fix', 'Configure an alarm to be generated and sent when an Endpoint has a change in posture status.

From the Web Admin portal:
1. Choose Administration >> System >> Logging >> Logging Categories.
2. Configure the "AAA Audit", "Failed Attempts", and "Posture and Client Provisioning Audit" categories to have the Targets field to have LogCollector selected at a minimum. If the environment has an additional SYSLOG server, it can be selected here as well.'
  impact 0.5
  ref 'DPMS Target Cisco ISE NAC'
  tag check_id: 'C-45859r714060_chk'
  tag severity: 'medium'
  tag gid: 'V-242584'
  tag rid: 'SV-242584r714062_rule'
  tag stig_id: 'CSCO-NC-000100'
  tag gtitle: 'SRG-NET-000015-NAC-000100'
  tag fix_id: 'F-45816r714061_fix'
  tag 'documentable'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
