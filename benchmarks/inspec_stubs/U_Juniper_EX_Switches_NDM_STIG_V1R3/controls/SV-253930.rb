control 'SV-253930' do
  title 'The Juniper EX switch must be configured to protect against known types of denial-of-service (DoS) attacks by employing organization-defined security safeguards.'
  desc 'DoS is a condition when a resource is not available for legitimate users. When this occurs, the organization either cannot accomplish its mission or must operate at degraded capacity.

This requirement addresses the configuration of network devices to mitigate the impact of DoS attacks that have occurred or are ongoing on device availability. For each network device, known and potential DoS attacks must be identified and solutions for each type implemented. A variety of technologies exist to limit or, in some cases, eliminate the effects of DoS attacks (e.g., limiting processes or restricting the number of sessions the device opens at one time). Employing increased capacity and bandwidth, combined with service redundancy, may reduce the susceptibility to some DoS attacks.

The security safeguards cannot be defined at the DoD-level because they vary according to the capabilities of the individual network devices and the security controls applied on the adjacent networks (for example, firewalls performing packet filtering to block DoS attacks).'
  desc 'check', 'Determine if the network device protects against or limits the effects of all known types of DoS attacks by employing organization-defined security safeguards.

Verify session and (if supported) rate limits for management connections.
SSH example:
[edit system services ssh]
connection-limit <1..250>;
rate-limit <1..250>;
Note: The SSH connection- and rate-limit directives affect secure file transfer protocols like SCP and SFTP.

NETCONF over SSH example:
[edit system services netconf]
ssh {
    connection-limit <1..250>;
    rate-limit <1..250>;
}
Note: Rate limiting is the permissible number of connections per one minute interval.

Verify policers (rate limiters) are appropriately applied to limit traffic; for example, to limit SSH connection attempts:
[edit firewall]
family inet {
    filter <filter name> {
        term 1 {
            from {
                destination-address {
                   <device OOBM or loopback address>;
                }
                source-prefix-list {
                    <management address list name>;
                }
                protocol tcp;
                destination-port 22;
                tcp-initial;
            }
            then {
                policer policer-32k;
                syslog;
                accept;
            }
        }
        term 2 {
            from {
                destination-address {
                   <device OOBM or loopback address>;
                }
                source-prefix-list {
                    <management address list name>;
                }
                protocol tcp;
                destination-port 22;
            }
            then {
                syslog;
                accept;
            }
        }
        term default {
            then {
                syslog;
                discard;
            }
        }
    }
}
family inet6 {
    filter <filter name-1> {
        term 1 {
            from {
                destination-address {
                   <device OOBM or loopback address>;
                }
                source-prefix-list {
                    <management address list name-1>;
                }
                next-header tcp;
                destination-port 22;
                tcp-initial;
            }
            then {
                policer policer-32k;
                syslog;
                accept;
            }
        }
        term 2 {
            from {
                destination-address {
                   <device OOBM or loopback address>;
                }
                source-prefix-list {
                    <management address list name-1>;
                }
                next-header tcp;
                destination-port 22;
            }
            then {
                syslog;
                accept;
            }
        }
        term default {
            then {
                syslog;
                discard;
            }
        }
    }
}
Note: Additional terms will be required for other services like SNMP.
policer policer-32k {
    if-exceeding {
        bandwidth-limit 32k;
        burst-size-limit 1500;
    }
    then discard;
}

[edit interfaces]
<OOBM interface> {
    unit 0 {
        family inet {
            filter {
                input <filter name>;
            }
            address <IPv4 address>/<mask>;
        }
        family inet6 {
            filter {
                input <filter name-1>;
            }
            address <IPv6 address>/<prefix>;
        }
    }
}
Note: Although the example filter is shown applied to the management interface, the filter can be also be applied to the loopback interface. If applying to loopback, ensure the filter terms account for all traffic, services, and protocols that must reach the routing engine (e.g., OSPF, BGP, SNMP, etc.).

If the network device does not protect against or limit the effects of all known types of DoS attacks by employing organization-defined security safeguards, this is a finding.'
  desc 'fix', 'Configure the network device to protect against or limit the effects of all known types of DoS attacks by employing organization-defined security safeguards.

SSH example:
set system services ssh connection-limit <1..250>
set system services ssh rate-limit <1..250>

NETCONF over SSH example:
set system services netconf ssh connection-limit <1..250>
set system services netconf ssh rate-limit <1..250>

Example firewall filters:
set firewall family inet filter <filter name> term 1 from destination-address <device OOBM or loopback address>
set firewall family inet filter <filter name> term 1 from source-prefix-list <management address list name>
set firewall family inet filter <filter name> term 1 from protocol tcp
set firewall family inet filter <filter name> term 1 from destination-port 22
set firewall family inet filter <filter name> term 1 from tcp-initial
set firewall family inet filter <filter name> term 1 then policer policer-32k
set firewall family inet filter <filter name> term 1 then syslog
set firewall family inet filter <filter name> term 1 then accept
set firewall family inet filter <filter name> term 2 from destination-address <device OOBM or loopback address>
set firewall family inet filter <filter name> term 2 from source-prefix-list <management address list name>
set firewall family inet filter <filter name> term 2 from protocol tcp
set firewall family inet filter <filter name> term 2 from destination-port 22
set firewall family inet filter <filter name> term 2 then syslog
set firewall family inet filter <filter name> term 2 then accept
set firewall family inet filter <filter name> term default then syslog
set firewall family inet filter <filter name> term default then discard
set firewall family inet6 filter <filter name-1> term 1 from destination-address <device OOBM or loopback address>
set firewall family inet6 filter <filter name-1> term 1 from source-prefix-list <management address list name-1>
set firewall family inet6 filter <filter name-1> term 1 from next-header tcp
set firewall family inet6 filter <filter name-1> term 1 from destination-port 22
set firewall family inet6 filter <filter name-1> term 1 from tcp-initial
set firewall family inet6 filter <filter name-1> term 1 then policer policer-32k
set firewall family inet6 filter <filter name-1> term 1 then syslog
set firewall family inet6 filter <filter name-1> term 1 then accept
set firewall family inet6 filter <filter name-1> term 2 from destination-address <device OOBM or loopback address>
set firewall family inet6 filter <filter name-1> term 2 from source-prefix-list <management address list name-1>
set firewall family inet6 filter <filter name-1> term 2 from next-header tcp
set firewall family inet6 filter <filter name-1> term 2 from destination-port 22
set firewall family inet6 filter <filter name-1> term 2 then syslog
set firewall family inet6 filter <filter name-1> term 2 then accept
set firewall family inet6 filter <filter name-1> term default then syslog
set firewall family inet6 filter <filter name-1> term default then discard

Example interface configuration:
set interfaces <OOBM interface> unit 0 family inet filter input <filter name>
set interfaces <OOBM interface> unit 0 family inet address <IPv4 address>/<mask>
set interfaces <OOBM interface> unit 0 family inet6 filter input <filter name-1>
set interfaces <OOBM interface> unit 0 family inet6 address <IPv6 address>/<prefix>'
  impact 0.5
  ref 'DPMS Target Juniper EX Series Switches NDM'
  tag check_id: 'C-57382r843821_chk'
  tag severity: 'medium'
  tag gid: 'V-253930'
  tag rid: 'SV-253930r879806_rule'
  tag stig_id: 'JUEX-NM-000530'
  tag gtitle: 'SRG-APP-000435-NDM-000315'
  tag fix_id: 'F-57333r843822_fix'
  tag 'documentable'
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
