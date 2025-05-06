control 'SV-217015' do
  title 'The Juniper router must be configured to authenticate all routing protocol messages using NIST-validated FIPS 140-2 message authentication code algorithm.'
  desc %q(A rogue router could send a fictitious routing update to convince a site's perimeter router to send traffic to an incorrect or even a rogue destination. This diverted traffic could be analyzed to learn confidential information about the site's network or used to disrupt the network's ability to communicate with other networks. This is known as a "traffic attraction attack" and is prevented by configuring neighbor router authentication for routing updates. However, using clear-text authentication provides little benefit since an attacker can intercept traffic and view the authentication key. This would allow the attacker to use the authentication key in an attack.

Since MD5 is vulnerable to "birthday" attacks and may be compromised, routing protocol authentication must use FIPS 140-2 validated algorithms and modules to encrypt the authentication key. This requirement applies to all IPv4 and IPv6 protocols that are used to exchange routing or packet forwarding information; this includes all Interior Gateway Protocols (such as OSPF, EIGRP, and IS-IS) and Exterior Gateway Protocols (such as BGP), MPLS-related protocols (such as LDP), and multicast-related protocols.)
  desc 'check', 'Review the router configuration to verify it is using a NIST-validated FIPS 140-2 message authentication code algorithm to authenticate routing protocol messages.

IS-IS Example:

security {
     …
    …
    …
    }
    authentication-key-chains {
        key-chain ISIS_KEY {
            key 1 {
                secret "$8$W8oXxdji.f5F-VQn"; ## SECRET-DATA
                start-time "2018-5-1.12:00:00 +0000";
                algorithm hmac-sha-1;
                options isis-enhanced;
            }
            key 2 {
                secret "$8$Q4953nCrlMLX-9A7V"; ## SECRET-DATA
                start-time "2018-9-1.12:00:00 +0000";
                algorithm hmac-sha-1;
                options isis-enhanced;
            }
            key 3 {
                secret "$8$UeiHmpu1Ehr.PSe"; ## SECRET-DATA
                start-time "2019-1-1.12:00:00 +0000";
                algorithm hmac-sha-1;
                options isis-enhanced;
            }
        }
    }
}

protocols {
    …
    …
    …
    isis {
        level 1 authentication-key-chain ISIS_KEY;
        level 2 authentication-key-chain ISIS_KEY;
        interface ge-0/0/0 {
            level 1 hello-authentication-key-chain ISIS_KEY;
            level 2 hello-authentication-key-chain ISIS_KEY;
        }
        interface lo0.0;
    }

BGP Example:

}
security {
    …
    …
    …
    }
    authentication-key-chains {
        key-chain BGP_KEY {
            key 1 {
                secret "$8$PTQnhclvMX3687"; ## SECRET-DATA
                start-time "2018-5-1.12:00:00 +0000";
            }
            key 2 {
                secret "$8$iq.5OBESyKfTlM"; ## SECRET-DATA
                start-time "2018-9-1.12:00:00 +0000";
            }
            key 3 {
                secret "$8$ZADjqAtOIRSk.hr"; ## SECRET-DATA
                start-time "2019-1-1.12:00:00 +0000";
            }
        }

protocols {
    bgp {
        group AS_2 {
            type external;
            peer-as 2;
            neighbor 11.1.25.2 {
                authentication-algorithm hmac-sha-1-96;
                authentication-key-chain BGP_KEY;
            }
            neighbor 11.1.1.1 {
                authentication-algorithm hmac-sha-1-96;
                authentication-key-chain BGP_KEY;
            }
        }
    }

OSPF Example:

IPsec authentication must be used to authenticate OSPF messages with a FIPS 140-2 message authentication code algorithm. 

Step 1: Verify the authentication algorithm in the IPsec security association as shown in the example below.

security {
    …
    …
    …
    ipsec {
        security-association IPSEC-SA1 {
            mode transport;
            manual {
                direction bidirectional {
                    protocol ah;
                    spi 256;
                    authentication {
                        algorithm hmac-sha1-96;
                        key ascii-text "$8$u6M6OEcrevL7-YaZUjHmF39B1hP5CuBRle"; ## SECRET-DATA
                    }
                }
            }
        }
    }

Step 2: Verify that an IPsec security association has been configured on the interfaces as shown in the following example:

protocols {
    …
    …
    …
    ospf {
        area 0.0.0.0 {
            interface ge-0/0/0 {
                   ipsec-sa IPSEC-SA1;
            }
            interface ge-0/1/0 {
                   ipsec-sa IPSEC-SA1;
            }
            interface lo0.0;
            interface ge-0/2/0 {
                   ipsec-sa IPSEC-SA1;
            }
        }
    }
    ospf3 {
        area 0.0.0.0 {
            interface ge-1/2/0 {
                   ipsec-sa IPSEC-SA1;
            }
        }
    }
}

If a NIST-validated FIPS 140-2 message authentication code algorithm is not being used to authenticate routing protocol messages, this is a finding.

Note: Juniper does not support FIPS 140-2 message authentication code algorithm for RIP.'
  desc 'fix', 'Configure routing protocol authentication to use a NIST-validated FIPS 140-2 message authentication code algorithm.

IS-IS Example:

[edit security authentication-key-chains]
set key-chain ISIS_KEY key 1 options isis-enhanced
set key-chain ISIS_KEY key 2 options isis-enhanced
set key-chain ISIS_KEY key 3 options isis-enhanced
set key-chain ISIS_KEY key 1 start-time 2018-05-01.12:00 algorithm hmac-sha-1 secret xxxxxxxxxxxxx
set key-chain ISIS_KEY key 2 start-time 2018-09-01.12:00 algorithm hmac-sha-1 secret xxxxxxxxxxxxx
set key-chain ISIS_KEY key 3 start-time 2019-01-01.12:00 algorithm hmac-sha-1 secret xxxxxxxxxxxxx

[edit protocols]
set isis level 1 authentication-key-chain ISIS_KEY
set isis interface ge-0/0/0 level 1 hello-authentication-key-chain ISIS_KEY
set isis interface ge-0/0/0 level 2 hello-authentication-key-chain ISIS_KEY

BGP Example:

[edit security authentication-key-chains]
set key-chain BGP_KEY key 1 start-time 2018-05-01.12:00 secret xxxxxxxxxxxxx
set key-chain BGP_KEY key 2 start-time 2018-09-01.12:00 secret xxxxxxxxxxxxx
set key-chain BGP_KEY key 3 start-time 2019-01-01.12:00 secret xxxxxxxxxxxxx

[edit protocols bgp group AS_5]
set neighbor 11.1.25.5 authentication-algorithm hmac-sha-1-96
set neighbor 11.1.25.5 authentication-key-chain BGP_KEY
set neighbor 11.1.1.1 authentication-algorithm hmac-sha-1-96
set neighbor 11.1.1.1 authentication-key-chain BGP_KEY

OSPF Example:

Configure IPsec Security Association
[edit security ipsec]
set security-association IPSEC-SA1
set security-association IPSEC-SA1 mode transport
set security-association IPSEC-SA1 manual direction bidirectional
set security-association IPSEC-SA1 manual direction bidirectional protocol ah
set security-association IPSEC-SA1 manual direction bidirectional spi 256 
set security-association IPSEC-SA1 manual direction bidirectional authentication algorithm hmac-sha1-96 key ascii-text 1234567890abcdefghij 

[edit protocols ospf area 0.0.0.0]
set interface ge-0/0/0 ipsec-sa IPSEC-SA1
set interface ge-0/1/0 ipsec-sa IPSEC-SA1
set interface ge-0/2/0 ipsec-sa IPSEC-SA1

[edit protocols ospf area 0.0.0.0]
set interface ge-1/2/0 ipsec-sa IPSEC-SA1'
  impact 0.5
  ref 'DPMS Target Juniper Router RTR'
  tag check_id: 'C-18244r296913_chk'
  tag severity: 'medium'
  tag gid: 'V-217015'
  tag rid: 'SV-217015r639663_rule'
  tag stig_id: 'JUNI-RT-000050'
  tag gtitle: 'SRG-NET-000168-RTR-000078'
  tag fix_id: 'F-18242r296914_fix'
  tag 'documentable'
  tag legacy: ['SV-101025', 'V-90815']
  tag cci: ['CCI-000803']
  tag nist: ['IA-7']
end
