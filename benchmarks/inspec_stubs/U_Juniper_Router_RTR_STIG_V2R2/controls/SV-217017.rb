control 'SV-217017' do
  title 'The Juniper router must be configured to have all non-essential capabilities disabled.'
  desc 'A compromised router introduces risk to the entire network infrastructure, as well as data resources that are accessible via the network. The perimeter defense has no oversight or control of attacks by malicious users within the network. Preventing network breaches from within is dependent on implementing a comprehensive defense-in-depth strategy, including securing each device connected to the network. This is accomplished by following and implementing all security guidance applicable for each node type. A fundamental step in securing each router is to enable only the capabilities required for operation.'
  desc 'check', 'Review the router configuration to determine if services not required for operation are enabled. Services such as finger, ftp, telnet must never be enabled; hence, they should not be shown under the system services hierarchy.

If J-web is not used for administrative access, the web-management services must not be configured as shown below.

If DHCP server is not being deployed on the router, the command dhcp-local-server must not be configured as shown below.

system {
    …
    …
    …
    services {
        web-management {
           https {
            interface ge-0/0/0.0;
           }
        }
        finger;
        ftp;
        ssh {
            protocol-version v2;
            macs [ hmac-sha1-96 hmac-sha2-256 hmac-sha2-512 ];
        }
        telnet;
        netconf {
            ssh;
        }
        dhcp-local-server {
            group DHCP_GROUP {
                interface ge-0/1/0.0;
            }
        }
    }

If unnecessary services and functions are enabled on the router, this is a finding.'
  desc 'fix', 'Remove unneeded services and functions from the router as shown below.

[edit system services]
delete telnet
[edit system services]
delete finger
[edit system services]
delete ftp'
  impact 0.3
  ref 'DPMS Target Juniper Router RTR'
  tag check_id: 'C-18246r296919_chk'
  tag severity: 'low'
  tag gid: 'V-217017'
  tag rid: 'SV-217017r639663_rule'
  tag stig_id: 'JUNI-RT-000070'
  tag gtitle: 'SRG-NET-000131-RTR-000035'
  tag fix_id: 'F-18244r296920_fix'
  tag 'documentable'
  tag legacy: ['SV-101029', 'V-90819']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
