control 'SV-253952' do
  title 'The Juniper EX switch must be configured to permit authorized users to select a user session to capture.'
  desc 'Without the capability to select a user session to capture/record or view/hear, investigations into suspicious or harmful events would be hampered by the volume of information captured. The volume of information captured may also adversely impact the operation for the network. Session audits may include port mirroring, tracking websites visited, and recording information and/or file transfers.'
  desc 'check', 'Verify if the switch configuration has an analyzer to capture ingress and egress packets from any designated access interface for the purpose of monitoring a specific user session.

Packet capture using the [edit forwarding-options analyzer <analyzer name>] configuration will only be present and enabled when actively monitoring sessions. 

If actively capturing packets, verify an analyzer is present.
[edit forwarding-options]
analyzer {
    <analyzer name> {
        input {
            ingress {
                interface <input interface>.<logical unit>;
                -or-
                interface irb.<logical unit>;
            }
            egress {
                interface <input interface>.<logical unit>;
                -or-
                interface irb.<logical unit>;
            }
        }
        output {
            interface <output interface>.<logical unit>;
        }
    }
}
Note: Simultaneously mirroring both ingress and egress traffic may exceed the output interface capacity. Packet mirroring consumes resources and should only be enabled when actively monitoring sessions.

If active monitoring is not currently required, the lack of an analyzer, or the presence of an inactive (disabled) analyzer, is not a finding.

If the switch is not configured to capture ingress and egress packets from a designated access interface, this is a finding.'
  desc 'fix', 'Enable the feature or configure the switch so that it is capable of capturing ingress and egress packets from any designated switch port for the purpose of monitoring a specific user session.

To capture packets from the L2 interface ge-0/0/0 and forward out the L2 interface ge-0/0/1, configure the switch similarly to the example:

set forwarding-options analyzer <analyzer name> input ingress interface <input interface>.<logical unit>
-or-
set forwarding-options analyzer <analyzer name> input ingress interface irb.<logical unit>

set forwarding-options analyzer <analyzer name> input egress interface <input interface>.<logical unit>
-or-
set forwarding-options analyzer <analyzer name> input egress interface irb.<logical unit>

set forwarding-options analyzer <analyzer name> output interface <output interface>.<logical unit>'
  impact 0.5
  ref 'DPMS Target Juniper EX Series Layer 2 Switch'
  tag check_id: 'C-57404r843887_chk'
  tag severity: 'medium'
  tag gid: 'V-253952'
  tag rid: 'SV-253952r843889_rule'
  tag stig_id: 'JUEX-L2-000050'
  tag gtitle: 'SRG-NET-000331-L2S-000001'
  tag fix_id: 'F-57355r843888_fix'
  tag 'documentable'
  tag cci: ['CCI-001919']
  tag nist: ['AU-14 a']
end
