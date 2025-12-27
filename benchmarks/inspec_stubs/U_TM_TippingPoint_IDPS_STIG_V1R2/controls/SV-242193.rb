control 'SV-242193' do
  title 'The TPS must block outbound traffic containing known and unknown DoS attacks by ensuring that security policies, signatures, rules, and anomaly detection techniques are applied to outbound communications traffic.'
  desc 'The TPS must include protection against DoS attacks that originate from inside the enclave which can affect either internal or external systems. These attacks may use legitimate or rogue endpoints from inside the enclave. 

Installation of TPS detection and prevention components (i.e., sensors) at key boundaries in the architecture mitigates the risk of DoS attacks. These attacks can be detected by matching observed communications traffic with patterns of known attacks and monitoring for anomalies in traffic volume/type.

To comply with this requirement, the TPS must inspect outbound traffic for indications of known and unknown DoS attacks. Sensor log capacity management, along with techniques which prevent the logging of redundant information during an attack, also guard against DoS attacks. This requirement is used in conjunction with other requirements which require configuration of security policies, signatures, rules, and anomaly detection techniques and are applicable to both inbound and outbound traffic.'
  desc 'check', %q(1. In the Trend Micro SMS, navigate to "Profiles" and "Inspection Profiles" and select the organization's profile. 
2. If there is not one configured, select "Default". 
3. Click "Search". 

Under "advanced DDoS", if a DDoS filter does not exist, this is a finding.)
  desc 'fix', %q(1. In the Trend Micro SMS, navigate to "Profiles" and "Inspection Profiles" and select the organization's profile. 
2. If there is not one configured, select "Default". 
3. Click "Search". 
4. Under "advanced DDoS", select New. 
   a. Under Filter Parameters, type a name.
   b. Select Block + Notify as the action set. 
   c. Determine which port-pair direction is the outbound direction. For example, if the outbound traffic direction is Port A to Port B, select "Port A to Port B" as the direction. 
   d. Select "Any" for the destination IP. 
   e. Select SYN Proxy Settings.
   f. Click "enabled". 
   g. Type a notification threshold of SYN transmits per second. The range is 1–10000. Consult with the ISSO to ensure this range will meet organizational policy. 
   h. Under an approved change window, select Distribute to the TPS.)
  impact 0.5
  ref 'DPMS Target Trend Micro TippingPoint IDPS'
  tag check_id: 'C-45468r710120_chk'
  tag severity: 'medium'
  tag gid: 'V-242193'
  tag rid: 'SV-242193r710122_rule'
  tag stig_id: 'TIPP-IP-000280'
  tag gtitle: 'SRG-NET-000192-IDPS-00140'
  tag fix_id: 'F-45426r710121_fix'
  tag 'documentable'
  tag cci: ['CCI-001095']
  tag nist: ['SC-5 (2)']
end
