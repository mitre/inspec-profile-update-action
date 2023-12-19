control 'SV-206713' do
  title 'The firewall must generate traffic log records when traffic is denied, restricted, or discarded.'
  desc 'Without generating log records that log usage of objects by subjects and other objects, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

Security objects are data objects that are controlled by security policy and bound to security attributes.

The firewall must not forward traffic unless it is explicitly permitted via security policy. Logging for firewall security-related sources such as screens and security policies must be configured separately. To ensure security objects such as firewall filters (i.e., rules, access control lists [ACLs], screens, and policies) send events to a syslog server and local logs, security logging must be configured one each firewall term.'
  desc 'check', 'View the configuration of the firewall or the central audit server log records.

Verify the firewall generates traffic log records when traffic is denied, restricted, or discarded.

If the firewall does not generate traffic log records for events when traffic is denied, restricted, or discarded, this is a finding.'
  desc 'fix', 'Configure the firewall central audit server stanza to generate traffic log records for events when traffic is denied, restricted, or discarded.'
  impact 0.5
  ref 'DPMS Target Firewall'
  tag check_id: 'C-6970r297918_chk'
  tag severity: 'medium'
  tag gid: 'V-206713'
  tag rid: 'SV-206713r604133_rule'
  tag stig_id: 'SRG-NET-000492-FW-000006'
  tag gtitle: 'SRG-NET-000492'
  tag fix_id: 'F-6970r297919_fix'
  tag 'documentable'
  tag legacy: ['V-79429', 'SV-94135']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
