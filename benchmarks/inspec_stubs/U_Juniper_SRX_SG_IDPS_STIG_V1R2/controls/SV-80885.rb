control 'SV-80885' do
  title 'The Juniper Networks SRX Series Gateway IDPS must block outbound traffic containing known and unknown DoS attacks by ensuring that rules are applied to outbound communications traffic.'
  desc 'The IDPS must include protection against DoS attacks that originate from inside the enclave which can affect either internal or external systems. These attacks may use legitimate or rogue endpoints from inside the enclave. 

Installation of IDPS detection and prevention components (i.e., sensors) at key boundaries in the architecture mitigates the risk of DoS attacks. These attacks can be detected by matching observed communications traffic with patterns of known attacks and monitoring for anomalies in traffic volume/type.

To comply with this requirement, the IDPS must inspect outbound traffic for indications of known and unknown DoS attacks. Sensor log capacity management along with techniques which prevent the logging of redundant information during an attack also guard against DoS attacks. This requirement is used in conjunction with other requirements which require configuration of security policies, signatures, rules, and anomaly detection techniques and are applicable to both inbound and outbound traffic.'
  desc 'check', 'Determine the names of the IDP policies by asking the site representative. From operational mode, enter the following command to verify outbound zones are configured with an IDP policy. 

show security policies

If zones bound to the outbound interfaces, including VPN zones, are not configured with an IDP policy, this is a finding.'
  desc 'fix', 'To enable IDP services on outbound traffic on the device, first create a security policy for the traffic flowing in one direction, then specify the action to be taken on traffic that matches conditions specified in the policy.

[edit security policies from-zone <trusted-zone1-name> to-zone <untrusted-zone-name> policy idp-app-policy-1]
set match source-address any destination-address any application any

[edit security policies from-zone <trusted-zone-name> to-zone untrusted-zone-name> policy <idp-app-policy-name>]
set then permit application-services idp'
  impact 0.5
  ref 'DPMS Target Juniper SRX SG IDPS'
  tag check_id: 'C-67039r1_chk'
  tag severity: 'medium'
  tag gid: 'V-66395'
  tag rid: 'SV-80885r1_rule'
  tag stig_id: 'JUSX-IP-000005'
  tag gtitle: 'SRG-NET-000192-IDPS-00140'
  tag fix_id: 'F-72471r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001095']
  tag nist: ['SC-5 (2)']
end
