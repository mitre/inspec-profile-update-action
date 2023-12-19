control 'SV-68881' do
  title 'The ALG providing content filtering must block outbound traffic containing known and unknown DoS attacks to protect against the use of internal information systems to launch any Denial of Service (DoS) attacks against other networks or endpoints.'
  desc 'DoS attacks can take multiple forms but have the common objective of overloading or blocking a network or host to deny or seriously degrade performance. If the network does not provide safeguards against DoS attack, network resources will be unavailable to users.

Installation of an ALG at key boundaries in the architecture mitigates the risk of DoS attacks. These attacks can be detected by matching observed communications traffic with patterns of known attacks and monitoring for anomalies in traffic volume/type.

The ALG must include protection against DoS attacks that originate from inside the enclave which can affect either internal or external systems. These attacks may use legitimate or rogue endpoints from inside the enclave. These attacks can be simple "floods" of traffic to saturate circuits or devices, malware that consumes CPU and memory on a device or causes it to crash, or a configuration issue that disables or impairs the proper function of a device. For example, an accidental or deliberate misconfiguration of a routing table can misdirect traffic for multiple networks.

To comply with this requirement, the ALG must monitor outbound traffic for indications of known and unknown DoS attacks. Audit log capacity management along with techniques which prevent the logging of redundant information during an attack also guard against DoS attacks.'
  desc 'check', 'If the ALG does not perform content filtering as part of the traffic management functions, this is not applicable.

Verify the ALG is configured to block outbound traffic containing known and unknown DoS attacks.

If the ALG does not block outbound traffic containing known and unknown DoS attacks, this is a finding.'
  desc 'fix', 'If the ALG performs content filtering as part of the traffic management functionality, configure the ALG to block outbound traffic containing known and unknown DoS attacks.'
  impact 0.5
  ref 'DPMS Target SRG-NET-ALG'
  tag check_id: 'C-55255r1_chk'
  tag severity: 'medium'
  tag gid: 'V-54635'
  tag rid: 'SV-68881r1_rule'
  tag stig_id: 'SRG-NET-000192-ALG-000121'
  tag gtitle: 'SRG-NET-000192-ALG-000121'
  tag fix_id: 'F-59491r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001094']
  tag nist: ['SC-5 (1)']
end
