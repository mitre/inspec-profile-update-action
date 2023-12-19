control 'SV-95655' do
  title 'AAA Services must be configured to disable non-essential modules.'
  desc 'It is detrimental for applications to provide, or install by default, functionality exceeding requirements or mission objectives. These unnecessary capabilities or services are often overlooked and therefore may remain unsecured. They increase the risk to the platform by providing additional attack vectors.

Applications are capable of providing a wide variety of functions and services. Some of the functions and services, provided by default, may not be necessary to support essential organizational operations (e.g., key missions, functions). 

Examples of non-essential capabilities include, but are not limited to, advertising software or browser plug-ins not related to requirements or providing a wide array of functionality not required for every mission, but cannot be disabled.'
  desc 'check', 'Determine if AAA Services are configured to disable non-essential modules.

If AAA Services are not configured to disable non-essential modules, this is a finding.'
  desc 'fix', 'Configure AAA Services to disable non-essential modules.'
  impact 0.5
  ref 'DPMS Target SRG-APP-AAA'
  tag check_id: 'C-80683r1_chk'
  tag severity: 'medium'
  tag gid: 'V-80945'
  tag rid: 'SV-95655r1_rule'
  tag stig_id: 'SRG-APP-000141-AAA-000670'
  tag gtitle: 'SRG-APP-000141-AAA-000670'
  tag fix_id: 'F-87801r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
