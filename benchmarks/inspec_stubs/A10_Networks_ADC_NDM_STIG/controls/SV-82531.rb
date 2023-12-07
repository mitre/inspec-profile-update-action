control 'SV-82531' do
  title 'The A10 Networks ADC must have command auditing enabled.'
  desc 'Reconstruction of harmful events or forensic analysis is not possible if audit records do not contain enough information. The organization must maintain audit trails in sufficient detail to reconstruct events to determine the cause and impact of compromise.

Organizations consider limiting the additional audit information to only that information explicitly needed for specific audit requirements. The additional information required is dependent on the type of information (i.e., sensitivity of the data and the environment within which it resides). At a minimum, the organization must audit full-text recording of privileged commands.'
  desc 'check', 'Review the device configuration.

The following command displays the configuration and includes an output modifier to filter on the word "audit":
show run | inc audit

If the output does not include "audit enable privilege", this is a finding.'
  desc 'fix', 'The following command enables command auditing:
audit enable privilege

The privilege option enables logging of Privileged EXEC commands also. Without this option, only configuration commands are logged. Use this option.'
  impact 0.3
  ref 'DPMS Target A10 Networks ADC NDM'
  tag check_id: 'C-68601r1_chk'
  tag severity: 'low'
  tag gid: 'V-68041'
  tag rid: 'SV-82531r1_rule'
  tag stig_id: 'AADC-NM-000032'
  tag gtitle: 'SRG-APP-000101-NDM-000231'
  tag fix_id: 'F-74157r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000135']
  tag nist: ['AU-3 (1)']
end
