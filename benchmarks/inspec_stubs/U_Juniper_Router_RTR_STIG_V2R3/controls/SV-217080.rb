control 'SV-217080' do
  title 'The Juniper P router must be configured to enforce a Quality-of-Service (QoS) policy in accordance with the QoS GIG Technical Profile.'
  desc 'Different applications have unique requirements and toleration levels for delay, jitter, bandwidth, packet loss, and availability. To manage the multitude of applications and services, a network requires a QoS framework to differentiate traffic and provide a method to manage network congestion. The Differentiated Services Model (DiffServ) is based on per-hop behavior by categorizing traffic into different classes and enabling each node to enforce a forwarding treatment to each packet as dictated by a policy.

Packet markings such as IP Precedence and its successor, Differentiated Services Code Points (DSCP), were defined along with specific per-hop behaviors for key traffic types to enable a scalable QoS solution. DiffServ QoS categorizes network traffic, prioritizes it according to its relative importance, and provides priority treatment based on the classification. It is imperative that end-to-end QoS is implemented within the IP core network to provide preferred treatment for mission-critical applications.'
  desc 'check', 'Review the router configuration and verify that it has been configured to enforce a QoS policy in accordance with the QoS GIG Technical Profile (GTP-0009). The router must be configured to use either configured or default Behavior Aggregate (BA) classifier on all interfaces as shown in the example below:

class-of-service {
    …
    …
    …
    }
    interfaces {
        ge-0/0/1 {
            unit 0 {
                classifiers {
                    dscp default;
                }
            }
        }
        ge-0/1/0 {
            unit 0 {
                classifiers {
                    dscp default;
                }
            }
        }
        ge-1/0/1 {
            unit 0 {
                classifiers {
                    dscp default;
                }
            }
        }
        ge-1/1/0 {
            unit 0 {
                classifiers {
                    dscp default;
                }
            }
        }

Note: The GTP QOS document (GTP-0009) can be downloaded via the following link: 
https://intellipedia.intelink.gov/wiki/Portal:GIG_Technical_Guidance/GTG_GTPs/GTP_Development_List

If the router is not configured to enforce a QoS policy in accordance with the QoS GIG Technical Profile, this is a finding.'
  desc 'fix', 'Configure all P router interfaces and PE core-facing interfaces to use a configured or the default BA classifier as shown in the example below.

[edit class-of-service interfaces]
set ge-0/0/1 unit 0 classifiers dscp default
set ge-0/1/0 unit 0 classifiers dscp default 
set ge-1/0/1 unit 0 classifiers dscp default
set ge-1/1/0 unit 0 classifiers dscp default

Note: The GTP QOS document (GTP-0009) can be downloaded via the following link: 
https://intellipedia.intelink.gov/wiki/Portal:GIG_Technical_Guidance/GTG_GTPs/GTP_Development_List'
  impact 0.3
  ref 'DPMS Target Juniper Router RTR'
  tag check_id: 'C-18309r297108_chk'
  tag severity: 'low'
  tag gid: 'V-217080'
  tag rid: 'SV-217080r604135_rule'
  tag stig_id: 'JUNI-RT-000750'
  tag gtitle: 'SRG-NET-000193-RTR-000114'
  tag fix_id: 'F-18307r297109_fix'
  tag 'documentable'
  tag legacy: ['SV-101151', 'V-90941']
  tag cci: ['CCI-001095']
  tag nist: ['SC-5 (2)']
end
