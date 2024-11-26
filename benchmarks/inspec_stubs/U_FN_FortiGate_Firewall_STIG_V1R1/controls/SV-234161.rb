control 'SV-234161' do
  title 'The FortiGate firewall must generate traffic log records when attempts are made to send packets between security zones that are not authorized to communicate.'
  desc 'Without generating log records specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

Access for different security levels maintains separation between resources (particularly stored data) of different security domains.

The firewall can be configured to use security zones configured with different security policies based on risk and trust levels. These zones can be leveraged to prevent traffic from one zone from sending packets to another zone. For example, information from certain IP sources will be rejected if the destination matches specified security zones that are not authorized.'
  desc 'check', 'Log in to the FortiGate GUI with Super-Admin privilege.

1. Click Log and Report.
2. Click Log Settings.
3. Verify the Log Settings for Event Logging and Local Traffic Log are configured to ALL.

In addition to System log settings, verify individual firewall policies are configured with the most suitable Logging Options.

1. Click Policy and Objects.
2. Click IPv4 or IPv6 Policy.
3. Verify all Policy rules are configured with Logging Options set to Log All Sessions (for most verbose logging).
4. Verify the Implicit Deny Policy is configured to Log Violation Traffic.

If the Traffic Log setting is not configured to ALL, and the Implicit Deny Policies are not configured to LOG VIOLATION TRAFFIC, this is a finding.'
  desc 'fix', 'Log in to the FortiGate GUI with Super-Admin privilege.

1. Click Log and Report.
2. Click Log Settings.
3. Configure the Log Settings for Local Traffic Log to ALL.
4. Click Apply.

In addition to these log settings, configure individual firewall policies with the most suitable Logging Options.

1. Click Policy and Objects.
2. Click IPv4 or IPv6 Policy.
3. Click +Create New to configure organization specific policies, with Action set to DENY.
4. Configure Logging Options to log All Sessions (for most verbose logging).
5. Ensure Enable this policy is toggled to right.
6. Click Implicit Deny Policy.
7. Click Edit.
8. Select Log Violation Traffic.
9. Click OK.'
  impact 0.5
  ref 'DPMS Target Fortinet FortiGate Firewall'
  tag check_id: 'C-37346r611481_chk'
  tag severity: 'medium'
  tag gid: 'V-234161'
  tag rid: 'SV-234161r628776_rule'
  tag stig_id: 'FNFG-FW-000165'
  tag gtitle: 'SRG-NET-000493-FW-000007'
  tag fix_id: 'F-37311r611482_fix'
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
