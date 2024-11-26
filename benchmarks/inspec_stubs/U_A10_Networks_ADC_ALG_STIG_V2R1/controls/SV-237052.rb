control 'SV-237052' do
  title 'The A10 Networks ADC, when used to load balance web applications, must examine incoming user requests against the URI White Lists.'
  desc 'Unrestricted traffic may contain malicious traffic, which poses a threat to an enclave or to other connected networks. Additionally, unrestricted traffic may transit a network, which uses bandwidth and other resources.

Access control policies and access control lists implemented on devices that control the flow of network traffic (e.g., application level firewalls and Web content filters), ensure the flow of traffic is only allowed from authorized sources to authorized destinations. Networks with different levels of trust (e.g., the Internet or CDS) must be kept separate.

The URI White List defines acceptable destination URIs allowed for incoming requests. The White List Check compares the URI of an incoming request against the rules contained in the URI White List policy file. Connection requests are accepted only if the URI matches a rule in the URI White List. Note: A URI Black List can also be configured, which takes priority over a URI White List. However, since deny-all, permit by exception is a fundamental principle, a URI White List is necessary.'
  desc 'check', 'If the device is not used to load balance web servers, this is not applicable.

Review the device configuration.

The following command displays WAF templates:
show slb template waf

If the configured WAF template does not have the "uri-wlistcheck" option configured, this is a finding.'
  desc 'fix', 'If the device is used to load balance web servers, configure the URI White List.

The following commands configure the ADC to compare incoming traffic against the URI White List:
slb template waf [template-name]
uri-wlistcheck [file-name]'
  impact 0.5
  ref 'DPMS Target A10 Networks ADC ALG'
  tag check_id: 'C-40271r639601_chk'
  tag severity: 'medium'
  tag gid: 'V-237052'
  tag rid: 'SV-237052r639603_rule'
  tag stig_id: 'AADC-AG-000103'
  tag gtitle: 'SRG-NET-000364-ALG-000122'
  tag fix_id: 'F-40234r639602_fix'
  tag 'documentable'
  tag legacy: ['SV-82491', 'V-68001']
  tag cci: ['CCI-002403']
  tag nist: ['SC-7 (11)']
end
