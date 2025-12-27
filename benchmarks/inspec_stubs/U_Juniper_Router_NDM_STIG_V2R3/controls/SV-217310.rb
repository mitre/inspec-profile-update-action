control 'SV-217310' do
  title 'The Juniper router must be configured to enforce approved authorizations for controlling the flow of management information within the device based on control policies.'
  desc 'A mechanism to detect and prevent unauthorized communication flow must be configured or provided as part of the system design. If management information flow is not enforced based on approved authorizations, the network device may become compromised. Information flow control regulates where management information is allowed to travel within a network device. The flow of all management information must be monitored and controlled so it does not introduce any unacceptable risk to the network device or data. 

Application-specific examples of enforcement occur in systems that employ rule sets or establish configuration settings that restrict information system services or message-filtering capability based on message content (e.g., implementing key word searches or using document characteristics).

Applications providing information flow control must be able to enforce approved authorizations for controlling the flow of management information within the system in accordance with applicable policy.'
  desc 'check', 'Review the router configuration to verify that it is compliant with this requirement. 

Step 1: Verify that an input filter has been configured for the loopback interfaces as shown in the example below.

interfaces {
    …
    …
    …
    }
    lo0 {
        unit 0 {
            family inet {
                filter {
                    input RESTRICT_MGMT_ACCESS;
                }
                address 2.2.2.2/32;
            }
         }
    }
}

Step 2: Verify that the filter restricts management traffic. The configuration example below restricts management access to specific IP addresses via SSH. 

filter RESTRICT_MGMT_ACCESS {
    term ALLOW_SSH {
        from {
            source-address {
                x.x.x.x/24;
            }
            protocol tcp;
            port ssh;
        }
        then accept;
    }
    term DENY_SSH {
        from {
            protocol tcp;
            port ssh;
        }
        then {
            log;
            discard;
        }
    }
} 

Note: Management and control plane traffic destined to the router is punted to the routing engine. Hence, applying the filter to the loopback ensures that this traffic can be monitored regardless of the ingress physical interface. 

If the Juniper router is not configured to enforce approved authorizations for controlling the flow of management information within the device based on control policies, this is a finding.'
  desc 'fix', 'Step 1: Configure the router to restrict management access to specific IP addresses via SSH as shown in the example below.

[edit firewall family inet]
set filter RESTRICT_MGMT_ACCESS term ALLOW_SSH from source-address x.x.x.x/24
set filter RESTRICT_MGMT_ACCESS term ALLOW_SSH from protocol tcp
set filter RESTRICT_MGMT_ACCESS term ALLOW_SSH from port ssh
set filter RESTRICT_MGMT_ACCESS term ALLOW_SSH then accept
set filter RESTRICT_MGMT_ACCESS term DENY_SSH from protocol tcp
set filter RESTRICT_MGMT_ACCESS term DENY_SSH from port ssh
set filter RESTRICT_MGMT_ACCESS term DENY_SSH then log
set filter RESTRICT_MGMT_ACCESS term DENY_SSH then discard

Step 2:  Apply the filter to the loopback interface.

[edit interfaces lo0 unit 0 family inet]
set filter input RESTRICT_MGMT_ACCESS

Note: Management and control plane traffic destined to the router is punted to the routing engine. Hence, applying the filter to the loopback ensures that this traffic can be monitored regardless of the ingress physical interface. 

Step 1: Configure the router to restrict management access to specific IP addresses via SSH as shown in the example below.

[edit firewall family inet]
set filter RESTRICT_MGMT_ACCESS term ALLOW_SSH from source-address x.x.x.x/24
set filter RESTRICT_MGMT_ACCESS term ALLOW_SSH from protocol tcp
set filter RESTRICT_MGMT_ACCESS term ALLOW_SSH from port ssh
set filter RESTRICT_MGMT_ACCESS term ALLOW_SSH then accept
set filter RESTRICT_MGMT_ACCESS term DENY_SSH from protocol tcp
set filter RESTRICT_MGMT_ACCESS term DENY_SSH from port ssh
set filter RESTRICT_MGMT_ACCESS term DENY_SSH then log
set filter RESTRICT_MGMT_ACCESS term DENY_SSH then discard

Step 2:  Apply the filter to the loopback interface.

[edit interfaces lo0 unit 0 family inet]
set filter input RESTRICT_MGMT_ACCESS

Note: Management and control plane traffic destined to the router is punted to the routing engine. Hence, applying the filter to the loopback ensures that this traffic can be monitored regardless of the ingress physical interface.'
  impact 0.5
  ref 'DPMS Target Juniper Router NDM'
  tag check_id: 'C-18537r296508_chk'
  tag severity: 'medium'
  tag gid: 'V-217310'
  tag rid: 'SV-217310r879533_rule'
  tag stig_id: 'JUNI-ND-000140'
  tag gtitle: 'SRG-APP-000038-NDM-000213'
  tag fix_id: 'F-18535r296509_fix'
  tag 'documentable'
  tag legacy: ['SV-101203', 'V-91103']
  tag cci: ['CCI-001368']
  tag nist: ['AC-4']
end
