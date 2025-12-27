control 'SV-205487' do
  title 'The Mainframe Product must be configured to disable non-essential capabilities.'
  desc 'It is detrimental for applications to provide, or install by default, functionality exceeding requirements or mission objectives. These unnecessary capabilities or services are often overlooked and therefore may remain unsecured. They increase the risk to the platform by providing additional attack vectors.

Applications are capable of providing a wide variety of functions and services. Some of the functions and services, provided by default, may not be necessary to support essential organizational operations (e.g., key missions, functions). 

Examples of non-essential capabilities include, but are not limited to, advertising software or browser plug-ins not related to requirements or providing a wide array of functionality not required for every mission, but cannot be disabled.'
  desc 'check', 'Refer to Mainframe Product installation documentation to determine sample and default demonstrative components.

Examine installation settings.

If there are any sample or default demonstrative components in the installation, this is a finding.'
  desc 'fix', 'Configure the Mainframe Product installation and/or configurations to remove sample and demonstrative components.'
  impact 0.5
  ref 'DPMS Target Mainframe Product'
  tag check_id: 'C-5753r299694_chk'
  tag severity: 'medium'
  tag gid: 'V-205487'
  tag rid: 'SV-205487r395853_rule'
  tag stig_id: 'SRG-APP-000141-MFP-000200'
  tag gtitle: 'SRG-APP-000141'
  tag fix_id: 'F-5753r299695_fix'
  tag 'documentable'
  tag legacy: ['SV-82815', 'V-68325']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
