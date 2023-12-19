control 'SV-234194' do
  title 'The FortiGate device must generate log records for a locally developed list of auditable events.'
  desc 'Auditing and logging are key components of any security architecture. Logging the actions of specific events provides a means to investigate an attack; to recognize resource utilization or capacity thresholds; or to identify an improperly configured network device. If auditing is not comprehensive, it will not be useful for intrusion monitoring, security investigations, and forensic analysis.'
  desc 'check', 'Log in to the FortiGate GUI with Super-Admin privilege.

1. Open a CLI console, via SSH or available from the GUI.
2. Run the following command:
     # show full-configuration log setting

Compare the output to the locally developed list to ensure enabled events match the local list.
         
3. Run the following command:
     # show full-configuration log eventfilter

Compare the output to the locally developed list to ensure enabled events match the local list.
        
If the FortiGate device does not generate log records for a locally developed list of auditable events, this is a finding.'
  desc 'fix', 'Obtain local audit list and enable event logging to match requirements within the list.
Log in to the FortiGate GUI with Super-Admin privilege.

1. Open a CLI console, via SSH or available from the GUI.
2. Run the following command and set to enable any events that match a requirement in the local policy:
     # config log setting
     #    set resolve-ip {enable | disable}
     #    set resolve-port {enable | disable}
     #    set log-user-in-upper {enable | disable}
     #    set fwpolicy-implicit-log {enable | disable}
     #    set fwpolicy6-implicit-log {enable | disable}
     #    set log-invalid-packet {enable | disable}
     #    set local-in-allow {enable | disable}
     #    set local-in-deny-unicast {enable | disable}
     #    set local-in-deny-broadcast {enable | disable}
     #    set local-out {enable | disable}
     #    set daemon-log {enable | disable}
     #    set neighbor-event {enable | disable}
     #    set brief-traffic-format {enable | disable}
     #    set user-anonymize {enable | disable}
     #    set expolicy-implicit-log {enable | disable}
     #    set log-policy-comment {enable | disable}
     #    set log-policy-name {enable | disable}
     #    end
     # config log eventfilter
     #    set event {enable | disable}
     #    set system {enable | disable}
     #    set vpn {enable | disable}
     #    set user {enable | disable}
     #    set router {enable | disable}
     #    set wireless-activity {enable | disable}
     #    set wan-opt {enable | disable}
     #    set endpoint {enable | disable}
     #    set ha {enable | disable}
     #    set compliance-check {enable | disable}
     #    set security-rating {enable | disable}
     #    set fortiextender {enable | disable}
     #    set connector {enable | disable}
     #    end'
  impact 0.5
  ref 'DPMS Target Fortinet FortiGate NDM'
  tag check_id: 'C-37379r611769_chk'
  tag severity: 'medium'
  tag gid: 'V-234194'
  tag rid: 'SV-234194r628777_rule'
  tag stig_id: 'FGFW-ND-000175'
  tag gtitle: 'SRG-APP-000516-NDM-000334'
  tag fix_id: 'F-37344r611770_fix'
  tag 'documentable'
  tag cci: ['CCI-000169', 'CCI-000366']
  tag nist: ['AU-12 a', 'CM-6 b']
end
