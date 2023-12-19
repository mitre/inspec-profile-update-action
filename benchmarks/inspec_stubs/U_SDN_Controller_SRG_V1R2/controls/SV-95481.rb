control 'SV-95481' do
  title 'The SDN controller must be configured to disable non-essential capabilities.'
  desc 'It is detrimental for network elements to provide, or enable by default, functionality exceeding requirements or mission objectives. These unnecessary capabilities or services are often overlooked and therefore may remain unsecured. They increase the risk to the platform by providing additional attack vectors.

Some of the functions and services that could be enabled may not be necessary to support essential organizational operations.'
  desc 'check', 'Review the SDN controller configuration to determine if services or functions not required for SDN controller operation are enabled. 

If unnecessary services and functions are enabled on the SDN controller, this is a finding.'
  desc 'fix', 'Remove unneeded services and functions from the SDN configuration. Removal is recommended because the service or function may be inadvertently enabled otherwise. However, if removal is not possible, disable the service or function.'
  impact 0.5
  ref 'DPMS Target SRG-NET-SDC'
  tag check_id: 'C-80507r1_chk'
  tag severity: 'medium'
  tag gid: 'V-80771'
  tag rid: 'SV-95481r1_rule'
  tag stig_id: 'SRG-NET-000131-SDN-000200'
  tag gtitle: 'SRG-NET-000131'
  tag fix_id: 'F-87625r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
