control 'SV-237061' do
  title 'If the Data Owner requires it, the A10 Networks ADC must be configured to perform CCN Mask, SSN Mask, and PCRE Mask Request checks.'
  desc 'If outbound communications traffic is not continuously monitored, hostile activity may not be detected and prevented. Output from application and traffic monitoring serves as input to continuous monitoring and incident response programs.

The A10 Networks ADC can be configured to mask data traversing outbound through the device. This is useful in preventing data exfiltration. If any data must be masked before it leaves the enclave (such as Credit Card Numbers, Social Security Numbers, or other sensitive information), a WAF template can be configured with CCN Mask, SSN Mask, and PCRE Mask Request checks. The Mask Request check depends on what information must be masked. This includes using Perl Compatible Regular Expressions (PCRE) for custom masks.'
  desc 'check', 'Review the device configuration and ask the device Administrator which templates are used for masking sensitive data.

The following command displays the configuration and filters the output on the WAF template section:
show run | sec slb template waf

If there is no WAF template with the required Mask Request checks, this is a finding.'
  desc 'fix', 'Review the system or enclave documentation and confer with the data owner(s) if necessary. If any data must be masked before it leaves the enclave (such as credit card numbers, Social Security numbers, or other sensitive information), configure the CCN Mask, SSN Mask, and PCRE Mask Request checks. 

These checks are applied to a WAF template.

The following command replaces all but the last four digits of credit card numbers with an “x” character:
ccn-mask

The following command replaces all but the last four digits of US Social Security numbers with an “x” character:
ssn-mask

The following command cloaks patterns in a response that match the specified PCRE pattern:
pcre-scrub [pcre-pattern] [keep-end [num-length] |keep-start [num-length] |mask [character]]'
  impact 0.5
  ref 'DPMS Target A10 Networks ADC ALG'
  tag check_id: 'C-40280r639628_chk'
  tag severity: 'medium'
  tag gid: 'V-237061'
  tag rid: 'SV-237061r639630_rule'
  tag stig_id: 'AADC-AG-000154'
  tag gtitle: 'SRG-NET-000512-ALG-000062'
  tag fix_id: 'F-40243r639629_fix'
  tag 'documentable'
  tag legacy: ['SV-82513', 'V-68023']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
