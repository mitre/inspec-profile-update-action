control 'SV-234352' do
  title 'The UEM server must be configured to disable non-essential capabilities.'
  desc 'It is detrimental for applications to provide, or install by default, functionality exceeding requirements or mission objectives. These unnecessary capabilities or services are often overlooked and therefore may remain unsecured. They increase the risk to the platform by providing additional attack vectors.

Applications are capable of providing a wide variety of functions and services. Some of the functions and services, provided by default, may not be necessary to support essential organizational operations (e.g., key missions, functions). 

Examples of non-essential capabilities include, but are not limited to, advertising software or browser plug-ins not related to requirements or providing a wide array of functionality not required for every mission, but cannot be disabled. 

Satisfies:FMT_SMF.1.1(2) c.2 
Reference:PP-MDM-411064'
  desc 'check', 'Verify the UEM server has disabled non-essential capabilities.

If the UEM server has not disabled non-essential capabilities, this is a finding.'
  desc 'fix', 'Configure the UEM server to be configured to disable non-essential capabilities.'
  impact 0.5
  ref 'DPMS Target Unified Endpoint Management Server'
  tag check_id: 'C-37537r614066_chk'
  tag severity: 'medium'
  tag gid: 'V-234352'
  tag rid: 'SV-234352r879587_rule'
  tag stig_id: 'SRG-APP-000141-UEM-000079'
  tag gtitle: 'SRG-APP-000141'
  tag fix_id: 'F-37502r614067_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
