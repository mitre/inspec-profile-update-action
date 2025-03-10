control 'SV-253951' do
  title 'The Juniper EX switch must be configured to manage excess bandwidth to limit the effects of packet flooding types of denial of service (DoS) attacks.'
  desc 'Denial of service is a condition when a resource is not available for legitimate users. Packet flooding DDoS attacks are referred to as volumetric attacks and have the objective of overloading a network or circuit to deny or seriously degrade performance, which denies access to the services that normally traverse the network or circuit. Volumetric attacks have become relatively easy to launch by using readily available tools such as Low Orbit Ion Cannon or by using botnets.

Measures to mitigate the effects of a successful volumetric attack must be taken to ensure that sufficient capacity is available for mission-critical traffic. Managing capacity may include, for example, establishing selected network usage priorities or quotas and enforcing them using rate limiting, quality of service (QoS), or other resource reservation control methods. These measures may also mitigate the effects of sudden decreases in network capacity that are the result of accidental or intentional physical damage to telecommunications facilities (such as cable cuts or weather-related outages).'
  desc 'check', 'Review the switch configuration to verify that QoS has been enabled to ensure that sufficient capacity is available for mission-critical traffic such as voice and enforce the traffic priorities specified by the Combatant Commanders/Services/Agencies.

By default, Junos implements a standard Class-of-Service (CoS) strategy. Although some devices implement different queues or queue numbers, generally there is at least a four-queue model with two active queues: 95 percent Best Effort (BE) and 5 percent Network Control (NC). Verify at least a third queue (Voice) is active with an appropriate bandwidth allocation. Verify Voice over Internet Protocol (VoIP) phones are connected to VoIP interfaces and there is a separate VoIP Virtual Local Area Network (VLAN).

For example, assume 20 percent VoIP traffic on "voip" VLAN 119 and normal production traffic is on "data" VLAN 150. VoIP traffic will use Expedited-Forwarding (EF) and Differentiated Services Codepoint (DSCP) values 44 (101110) and 36 (100100).

Verify the VoIP VLAN is available.
[edit vlans]
data {
    vlan-id 150;
}
voip {
    vlan-id 119;
}

Verify the interfaces with connected VoIP phones are configured.
[edit interfaces]
<VoIP phone int-1> {
    unit <logical unit> {
        family ethernet-switching {
            vlan {
                members data;
            }
        }
    }
}
[edit switch-options]
voip {
    interface <VoIP phone int-1>.<logical unit> {
        vlan voip;
        forwarding-class (expedited-forwarding|assured-forwarding);
    }
}
Note: The example forwarding class (FC) names (EF and AF spelled out above) are generally available on all switches. To use a custom FC name (e.g., "voip"), the default CoS must be modified. The only requirement is that the assigned FC must be available under [edit class-of-service].

Verify the CoS strategy includes support for the assigned VoIP VLAN. From the configured interface example above, assume "expedited-forwarding" using DSCP values 44 (101110) and 36 (100100) are used for VoIP traffic. Traffic must be classified (placed into forwarding classes / queues) on ingress and scheduled (shaped) on egress. 
[edit class-of-service]
classifiers {
    dscp voip-classifier {
        import default;
        forwarding-class expedited-forwarding {
            loss-priority low code-points [ 101110 100100 ];
        }
    }
}
interfaces {
    <VoIP phone int-1> {
        scheduler-map voip-map;
        unit <logical unit> {
            classifiers {
                dscp voip-classifier;
            }
        }
    }
    <uplink interface> {
        scheduler-map voip-map;
        unit <logical unit> {
            classifiers {
                dscp voip-classifier;
            }
    }
}
scheduler-maps {
    voip-map {
        forwarding-class best-effort scheduler be-scheduler;
        forwarding-class expedited-forwarding scheduler ef-scheduler;
        forwarding-class network-control scheduler nc-scheduler;
    }
}
schedulers {
    be-scheduler {
        transmit-rate {
            remainder;
        }
        priority low;
    }
    ef-scheduler {
        shaping-rate percent 20;
        priority strict-high;
    }
    nc-scheduler {
        shaping-rate percent 5;
        priority strict-high;
    }
}
Note: The example CoS names, scheduler rates, and DSCP values must not be considered requirements. The names, rates, and values must be appropriately configured for the target environment.

If the switch is not configured to implement a QoS policy, this is a finding.'
  desc 'fix', 'Implement a QoS policy for traffic prioritization and bandwidth reservation. This policy must enforce the traffic priorities specified by the Combatant Commanders/Services/Agencies.

Configure the VLANs:
set vlans <data VLAN> vlan-id <data VLAN ID>
set vlans <VoIP VLAN> vlan-id <VoIP VLAN ID>

Configure the VoIP interface(s):
set interfaces <interface name> unit 0 family ethernet-switching interface-mode access
set interfaces <interface name> unit 0 family ethernet-switching vlan members <data VLAN>
set switch-options voip interface <interface name>.0 vlan <VoIP VLAN>
set switch-options voip interface <interface name>.0 forwarding-class <VoIP forwarding class>

Configure CoS:
set class-of-service classifiers dscp <VoIP classifier name> import default
set class-of-service classifiers dscp <VoIP classifier name> forwarding-class <VoIP forwarding class> loss-priority low code-points <DSCP code point>
set class-of-service classifiers dscp <VoIP classifier name> forwarding-class <VoIP forwarding class> loss-priority low code-points <DSCP code point> (optional - only if multiple DSCP values are used)
set class-of-service interfaces <VoIP interface> scheduler-map <VoIP scheduler map>
set class-of-service interfaces <VoIP interface> unit 0 classifiers dscp <VoIP classifier name>
set class-of-service interfaces <uplink interface> scheduler-map <VoIP scheduler map>
set class-of-service interfaces <uplink interface> unit 0 classifiers dscp <VoIP classifier name>
set class-of-service scheduler-maps <VoIP scheduler map> forwarding-class best-effort scheduler <scheduler name> (e.g. be-scheduler)
set class-of-service scheduler-maps <VoIP scheduler map> forwarding-class <VoIP forwarding class> scheduler <scheduler name> (e.g. ef-scheduler)
set class-of-service scheduler-maps <VoIP scheduler map> forwarding-class network-control scheduler <scheduler name> (e.g. nc-scheduler)
set class-of-service schedulers <be-scheduler name> transmit-rate (exact <value> | percent (0..100) | remainder)
set class-of-service schedulers <be-scheduler name> priority (high | low | medium-high | medium-low | strict-high)
set class-of-service schedulers <ef-scheduler name> shaping-rate percent (0..100)
set class-of-service schedulers <ef-scheduler name> priority (high | low | medium-high | medium-low | strict-high)
set class-of-service schedulers <nc-scheduler name> shaping-rate percent (0..100)
set class-of-service schedulers <nc-scheduler name> priority (high | low | medium-high | medium-low | strict-high)

Note: The classifier method (ToS bit, DSCP marking, etc.) and values, interfaces, priorities, and rates must be appropriate for the target environment.'
  impact 0.5
  ref 'DPMS Target Juniper EX Series Layer 2 Switch'
  tag check_id: 'C-57403r843884_chk'
  tag severity: 'medium'
  tag gid: 'V-253951'
  tag rid: 'SV-253951r843886_rule'
  tag stig_id: 'JUEX-L2-000040'
  tag gtitle: 'SRG-NET-000193-L2S-000020'
  tag fix_id: 'F-57354r843885_fix'
  tag 'documentable'
  tag cci: ['CCI-001095']
  tag nist: ['SC-5 (2)']
end
