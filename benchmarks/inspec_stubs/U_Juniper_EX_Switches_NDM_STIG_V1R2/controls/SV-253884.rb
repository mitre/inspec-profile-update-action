control 'SV-253884' do
  title 'The Juniper EX switch must be configured to enforce approved authorizations for controlling the flow of management information within the network device based on information flow control policies.'
  desc 'A mechanism to detect and prevent unauthorized communication flow must be configured or provided as part of the system design. If management information flow is not enforced based on approved authorizations, the network device may become compromised. Information flow control regulates where management information is allowed to travel within a network device. The flow of all management information must be monitored and controlled so it does not introduce any unacceptable risk to the network device or data. 

Application-specific examples of enforcement occur in systems that employ rule sets or establish configuration settings that restrict information system services or message-filtering capability based on message content (e.g., implementing key word searches or using document characteristics).

Applications providing information flow control must be able to enforce approved authorizations for controlling the flow of management information within the system in accordance with applicable policy.'
  desc 'check', "Review the network device configuration to determine if it enforces approved authorizations for controlling the flow of management information within the network device based on information flow control policies.

Verify the switch permits administrative access only from the authorized management network(s). Verify filters and terms account for all authorized management traffic.

Example prefix-list defining the management networks. Prefix lists are not required because IP addresses can be directly embedded into terms, but they define a set of IP addresses once that permits use across multiple terms.
[edit policy-options]
prefix-list ipv4-management {
    <IPv4 MGT subnet/mask>;
}
prefix-list ipv6-management {
    <IPv6 MGT subnet/prefix>;
}

Example firewall filter for SSH traffic:
[edit firewall]
family inet {
    filter permit-management-ipv4 {
        term 1 {
            from {
                destination-address {
                   <OOBM IPv4 address>;
                }
                source-address {  << Example embedded addresses using the 'source-address' match criterion
                     <IPv4 MGT subnet/mask>;
                }
                --or--
                source-prefix-list { << Example inherited addresses using the 'source-prefix-list' match criterion
                    ipv4-management;
                }
                protocol tcp;
                destination-port 22;
            }
            then {
                syslog;
                accept;
            }
        }
        term 2 {
            then {
                syslog;
                discard;
            }
        }
    }
}
family inet6 {
    filter permit-management-ipv6 {
        term 1 {
            from {
                destination-address {
                   <OOBM IPv6 address>;
                }
                source-address {  << Example embedded addresses using the 'source-address' match criterion
                     <IPv6 MGT subnet/prefix>;
                }
                --or--
                source-prefix-list { << Example inherited addresses using the 'source-prefix-list' match criterion
                    ipv6-management;
                }
                next-header tcp;
                destination-port 22;
            }
            then {
                syslog;
                accept;
            }
        }
        term 2 {
            then {
                syslog;
                discard;
            }
        }
    }
}
Note: Additional terms will be required for other services like SNMP, RADIUS, or syslog.

Example firewall filter applied to the OOBM interface. Juniper devices use different OOBM interface names depending upon platform (fxp0 used in the example):
[edit interfaces]
fxp0 {
    unit 0 {
        family inet {
            filter {
                input permit-management-ipv4;
            }
            address  <OOBM IPv4 address>/<mask>;
        }
        family inet6 {
            filter {
                input permit-management-ipv6;
            }
            address  <OOBM IPv6 address>/<prefix>;
        }
    }
}
Note: Although the example filter is shown applied to the management interface, the filter can also be applied to the loopback interface (lo0). If applying to loopback, ensure the filter terms account for all traffic, services, and protocols that must reach the routing engine (e.g., OSPF, BGP, SNMP, etc.).

If the switch does not enforce approved authorizations for controlling the flow of management information within the device based on information control policies, this is a finding."
  desc 'fix', 'Configure the network device to enforce approved authorizations for controlling the flow of management information within the network device based on information flow control policies.

Example MGT networks:
set policy-options prefix-list ipv4-management <IPv4 MGT subnet/mask>
set policy-options prefix-list ipv6-management <IPv6 MGT subnet/prefix>

Example firewall filters:
set firewall family inet filter permit-management-ipv4 term 1 from destination-address  <OOBM IPv4 address>
set firewall family inet filter permit-management-ipv4 term 1 from source-prefix-list ipv4-management
set firewall family inet filter permit-management-ipv4 term 1 from protocol tcp
set firewall family inet filter permit-management-ipv4 term 1 from destination-port 22
set firewall family inet filter permit-management-ipv4 term 1 then syslog
set firewall family inet filter permit-management-ipv4 term 1 then accept
set firewall family inet filter permit-management-ipv4 term 2 then syslog
set firewall family inet filter permit-management-ipv4 term 2 then discard
set firewall family inet6 filter permit-management-ipv6 term 1 from destination-address  <OOBM IPv6 address>
set firewall family inet6 filter permit-management-ipv6 term 1 from source-prefix-list ipv6-management
set firewall family inet6 filter permit-management-ipv6 term 1 from next-header tcp
set firewall family inet6 filter permit-management-ipv6 term 1 from destination-port 22
set firewall family inet6 filter permit-management-ipv6 term 1 then syslog
set firewall family inet6 filter permit-management-ipv6 term 1 then accept
set firewall family inet6 filter permit-management-ipv6 term 2 then syslog
set firewall family inet6 filter permit-management-ipv6 term 2 then discard

Example interface configuration:
set interfaces fxp0 unit 0 family inet filter input permit-management-ipv4
set interfaces fxp0 unit 0 family inet address  <OOBM IPv4 address>/<mask>
set interfaces fxp0 unit 0 family inet6 filter input permit-management-ipv6
set interfaces fxp0 unit 0 family inet6 address  <OOBM IPv6 address>/<prefix>'
  impact 0.5
  ref 'DPMS Target Juniper EX Series Switches NDM'
  tag check_id: 'C-57336r843683_chk'
  tag severity: 'medium'
  tag gid: 'V-253884'
  tag rid: 'SV-253884r843685_rule'
  tag stig_id: 'JUEX-NM-000070'
  tag gtitle: 'SRG-APP-000038-NDM-000213'
  tag fix_id: 'F-57287r843684_fix'
  tag 'documentable'
  tag cci: ['CCI-001368']
  tag nist: ['AC-4']
end
