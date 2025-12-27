control 'SV-45593' do
  title 'The IDPS must block outbound traffic containing known and unknown DoS attacks by ensuring that security policies, signatures, rules, and anomaly detection techniques are applied to outbound communications traffic.'
  desc 'The IDPS must include protection against DoS attacks that originate from inside the enclave which can affect either internal or external systems. These attacks may use legitimate or rogue endpoints from inside the enclave. 

Installation of IDPS detection and prevention components (i.e., sensors) at key boundaries in the architecture mitigates the risk of DoS attacks. These attacks can be detected by matching observed communications traffic with patterns of known attacks and monitoring for anomalies in traffic volume/type.

To comply with this requirement, the IDPS must inspect outbound traffic for indications of known and unknown DoS attacks. Sensor log capacity management along with techniques which prevent the logging of redundant information during an attack also guard against DoS attacks. This requirement is used in conjunction with other requirements which require configuration of security policies, signatures, rules, and anomaly detection techniques and are applicable to both inbound and outbound traffic.'
  desc 'check', 'Verify the IDPS blocks outbound traffic containing known and unknown DoS attacks by ensuring that security policies, signatures, rules, and anomaly detection techniques are applied to outbound communications traffic. 

If the IDPS does not block outbound traffic containing known and unknown DoS attacks, by ensuring that security policies, signatures, rules, and anomaly detection techniques are applied to outbound communications traffic, this is a finding.'
  desc 'fix', 'Configure the IDPS to block outbound traffic containing known and unknown DoS attacks, by ensuring that security policies, signatures, rules, and anomaly detection techniques are applied to outbound communications traffic.'
  impact 0.5
  ref 'DPMS Target SRG-NET-IDPS'
  tag check_id: 'C-42952r2_chk'
  tag severity: 'medium'
  tag gid: 'V-34707'
  tag rid: 'SV-45593r2_rule'
  tag stig_id: 'SRG-NET-000192-IDPS-00140'
  tag gtitle: 'SRG-NET-000192-IDPS-00140'
  tag fix_id: 'F-38991r4_fix'
  tag 'documentable'
  tag cci: ['CCI-001095']
  tag nist: ['SC-5 (2)']
end
