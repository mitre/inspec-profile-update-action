control 'SV-206759' do
  title 'The Voice Video Endpoint must be configured to disable or remove non-essential capabilities.'
  desc 'It is detrimental for Voice Video Endpoints when unnecessary features are enabled by default. Often these features are enabled by default with functionality exceeding requirements or mission objectives. These unnecessary capabilities or services are often overlooked and therefore may remain unsecured. They increase the risk to the platform by providing additional attack vectors.

Network elements are capable of providing a wide variety of functions and services. Some of the functions and services, provided by default, may not be necessary to support essential organizational operations (e.g., key missions, functions).'
  desc 'check', 'Verify the Voice Video Endpoint is configured to disable or remove non-essential capabilities. Non-essential capabilities would include peer services and other functions not directly pertaining to Voice Video Endpoint functionality.

If the Voice Video Endpoint cannot be configured to disable or remove non-essential capabilities, this is a finding.'
  desc 'fix', 'Configure the Voice Video Endpoint to disable or remove non-essential capabilities.'
  impact 0.5
  ref 'DPMS Target Voice Video Endpoint'
  tag check_id: 'C-7015r363800_chk'
  tag severity: 'medium'
  tag gid: 'V-206759'
  tag rid: 'SV-206759r604140_rule'
  tag stig_id: 'SRG-NET-000131-VVEP-00056'
  tag gtitle: 'SRG-NET-000131'
  tag fix_id: 'F-7015r363801_fix'
  tag 'documentable'
  tag legacy: ['SV-81283', 'V-66793']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
