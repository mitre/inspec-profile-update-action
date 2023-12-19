control 'SV-79721' do
  title 'The DataPower Gateway providing content filtering must not have a front side handler configured facing an internal network.'
  desc 'DoS attacks can take multiple forms but have the common objective of overloading or blocking a network or host to deny or seriously degrade performance. If the network does not provide safeguards against DoS attack, network resources will be unavailable to users.

Installation of an ALG at key boundaries in the architecture mitigates the risk of DoS attacks. These attacks can be detected by matching observed communications traffic with patterns of known attacks and monitoring for anomalies in traffic volume/type.

The ALG must include protection against DoS attacks that originate from inside the enclave which can affect either internal or external systems. These attacks may use legitimate or rogue endpoints from inside the enclave. These attacks can be simple "floods" of traffic to saturate circuits or devices, malware that consumes CPU and memory on a device or causes it to crash, or a configuration issue that disables or impairs the proper function of a device. For example, an accidental or deliberate misconfiguration of a routing table can misdirect traffic for multiple networks.

To comply with this requirement, the ALG must monitor outbound traffic for indications of known and unknown DoS attacks. Audit log capacity management along with techniques which prevent the logging of redundant information during an attack also guard against DoS attacks.'
  desc 'check', 'From the initial Web interface screen (the Control Panel), select Objects >> Protocol Handlers >>HTTPS Front Side Handler.

Click on each of the Handlers in the list that appears >> Click the Advanced tab of the Handler configuration >> Verify that there is an Access Control List selected >> Click the ellipses (…) button beside the list.

On the Access Control List page, click the Entry tab >> Verify that the network segments representing internal networks are denied.

If these items are not configured, this is a finding.'
  desc 'fix', 'From the initial Web interface screen (the Control Panel), select Objects >> Protocol Handlers >> HTTPS Front Side Handler. 
 
Click on each of the Handlers in the list that appears >> Click the Advanced tab of the Handler configuration.
 
For the Access Control List field, click “+” to create a new ACL >> Enter a name for the List >> Click the Entry tab >> Click Add >> Select Deny and set the Address Range to network segments representing internal networks >> Click Apply.'
  impact 0.5
  ref 'DPMS Target IBM DataPower XI52 ALG'
  tag check_id: 'C-65859r1_chk'
  tag severity: 'medium'
  tag gid: 'V-65231'
  tag rid: 'SV-79721r1_rule'
  tag stig_id: 'WSDP-AG-000045'
  tag gtitle: 'SRG-NET-000192-ALG-000121'
  tag fix_id: 'F-71171r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001094']
  tag nist: ['SC-5 (1)']
end
