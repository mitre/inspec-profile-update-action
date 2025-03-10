control 'SV-234160' do
  title 'The FortiGate firewall must generate traffic log records when traffic is denied, restricted, or discarded.'
  desc 'Without generating log records that log usage of objects by subjects and other objects, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

Security objects are data objects that are controlled by security policy and bound to security attributes.

The firewall must not forward traffic unless it is explicitly permitted via security policy. Logging for firewall security-related sources such as screens and security policies must be configured separately. To ensure security objects such as firewall filters (i.e., rules, access control lists [ACLs], screens, and policies) send events to a syslog server and local logs, security logging must be configured on each firewall term.'
  desc 'check', 'Log in to the FortiGate GUI with Super-Admin privilege.

1. Click Log and Report.
2. Click Log Settings.
3. Verify the Log Settings for Event Logging is configured to ALL.

In addition to System log settings, verify that individual firewall policies are configured with the most suitable Logging Options.

1. Click Policy and Objects.
2. Click IPv4 or IPv6 Policy.
3. Verify all Policy rules are configured with Logging Options set to Log All Sessions (for most verbose logging).
4. Verify the Implicit Deny Policy is configured to Log Violation Traffic.

If the Traffic Log setting is not configured to ALL, and the Implicit Deny Policies are not configured to LOG VIOLATION TRAFFIC, this is a finding.'
  desc 'fix', 'Log in to the FortiGate GUI with Super-Admin privilege.

1. Click Log and Report.
2. Click Log Settings.
3. Configure the Log Settings for Forward Traffic Log to ALL.
4. Click Apply.

In addition to these log settings, configure individual firewall policies with the most suitable Logging Options.

1. Click Policy and Objects.
2. Click IPv4 or IPv6 Policy.
3. For each policy, configure Logging Options for Log Allowed Traffic to log All Sessions (for most verbose logging).
4. Ensure the Enable this policy is toggled to right.
5. Configure the Implicit Deny Policy to Log Violation Traffic.
6. Click OK.'
  impact 0.5
  ref 'DPMS Target Fortinet FortiGate Firewall'
  tag check_id: 'C-37345r611478_chk'
  tag severity: 'medium'
  tag gid: 'V-234160'
  tag rid: 'SV-234160r628776_rule'
  tag stig_id: 'FNFG-FW-000160'
  tag gtitle: 'SRG-NET-000492-FW-000006'
  tag fix_id: 'F-37310r611479_fix'
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
