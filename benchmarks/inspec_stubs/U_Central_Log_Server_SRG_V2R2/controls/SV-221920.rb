control 'SV-221920' do
  title 'The Central Log Server must be configured to disable non-essential capabilities.'
  desc 'It is detrimental for applications to provide, or install by default, functionality exceeding requirements or mission objectives. These unnecessary capabilities or services are often overlooked and therefore may remain unsecured. They increase the risk to the platform by providing additional attack vectors.

Applications are capable of providing a wide variety of functions and services. Some of the functions and services, provided by default, may not be necessary to support essential organizational operations (e.g., key missions, functions). 

Examples of non-essential capabilities include, but are not limited to, advertising software or browser plug-ins not related to requirements or providing a wide array of functionality not required for every mission, but cannot be disabled.'
  desc 'check', 'Examine the configuration.

Verify that the Central Log Server is configured to disable non-essential capabilities.

If the Central Log Server is not configured to disable non-essential capabilities, this is a finding.'
  desc 'fix', 'Configure the Central Log Server to disable non-essential capabilities.'
  impact 0.5
  ref 'DPMS Target Central Log Server'
  tag check_id: 'C-23635r420102_chk'
  tag severity: 'medium'
  tag gid: 'V-221920'
  tag rid: 'SV-221920r420104_rule'
  tag stig_id: 'SRG-APP-000141-AU-000090'
  tag gtitle: 'SRG-APP-000141'
  tag fix_id: 'F-23624r420103_fix'
  tag 'documentable'
  tag legacy: ['SV-109173', 'V-100069']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
