control 'SV-237051' do
  title 'The A10 Networks ADC must enable DDoS filters.'
  desc 'If the network does not provide safeguards against DoS attacks, network resources will be unavailable to users. Installation of content filtering gateways and application layer firewalls at key boundaries in the architecture mitigates the risk of DoS attacks. These attacks can be detected by matching observed communications traffic with patterns of known attacks and monitoring for anomalies in traffic volume, type, or protocol usage. Detection components that use signatures can detect known attacks by using known attack signatures. Signatures are usually obtained from and updated by the vendor.'
  desc 'check', 'Review the device configuration.

The following command displays the device configuration and filters the output on the string "anomaly-drop":
show run | inc anomaly-drop

The output should display the following commands:
ip anomaly-drop ip-option
ip anomaly-drop land-attack
ip anomaly-drop ping-of-death
ip anomaly-drop frag
ip anomaly-drop tcp-no-flag
ip anomaly-drop tcp-syn-fin
ip anomaly-drop tcp-syn-frag
ip anomaly-drop out-of-sequence [threshold]
ip anomaly-drop ping-of-death
ip anomaly-drop zero-window [threshold]
ip anomaly-drop bad-content

If the output does not show these commands, this is a finding.'
  desc 'fix', 'The following commands configure DDoS filters:
ip anomaly-drop ip-option
ip anomaly-drop land-attack
ip anomaly-drop ping-of-death
ip anomaly-drop frag
ip anomaly-drop tcp-no-flag
ip anomaly-drop tcp-syn-fin
ip anomaly-drop tcp-syn-frag
ip anomaly-drop out-of-sequence [threshold]
ip anomaly-drop ping-of-death
ip anomaly-drop zero-window [threshold]
ip anomaly-drop bad-content

Note: Thresholds are specific to the expected traffic for the system or enclave.'
  impact 0.5
  ref 'DPMS Target A10 Networks ADC ALG'
  tag check_id: 'C-40270r639598_chk'
  tag severity: 'medium'
  tag gid: 'V-237051'
  tag rid: 'SV-237051r639600_rule'
  tag stig_id: 'AADC-AG-000101'
  tag gtitle: 'SRG-NET-000362-ALG-000126'
  tag fix_id: 'F-40233r639599_fix'
  tag 'documentable'
  tag legacy: ['SV-82489', 'V-67999']
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
