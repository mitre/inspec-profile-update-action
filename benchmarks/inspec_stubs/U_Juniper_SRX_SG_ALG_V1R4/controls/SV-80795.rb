control 'SV-80795' do
  title 'The Juniper SRX Services Gateway Firewall must generate audit records when unsuccessful attempts to access security zones occur.'
  desc 'Without generating log records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident, or identify those responsible for one.

Access for different security levels maintains separation between resources (particularly stored data) of different security domains.

The Juniper SRX Firewall implements security zones which are configured with different security policies based on risk and trust levels.'
  desc 'check', 'To verify what is logged in the Syslog, view the Syslog server (Syslog server configuration is out of scope for this STIG); however, the reviewer must also verify that packets are being logged to the local log using the following commands.

From operational mode, enter the following command.

show firewall log

View the Action column; the configured action of the term matches the action taken on the packet: A (accept), D (discard).

If events in the log do not reflect the action taken on the packet, this is a finding.'
  desc 'fix', 'Include the log and/or syslog action in all zone configurations to log attempts to access zones. To get traffic logs from permitted sessions, add "then log session-close" to the policy. To get traffic logs from denied sessions, add "then log session-init" to the policy.

set security policies from-zone <zone_name> to-zone <zone_name> policy <policy_name> then log

Example:
set security policies from-zone untrust to-zone trust policy default-deny then log'
  impact 0.5
  ref 'DPMS Target Juniper SRX SG ALG'
  tag check_id: 'C-66951r1_chk'
  tag severity: 'medium'
  tag gid: 'V-66305'
  tag rid: 'SV-80795r1_rule'
  tag stig_id: 'JUSX-AG-000037'
  tag gtitle: 'SRG-NET-000493-ALG-000028'
  tag fix_id: 'F-72381r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
