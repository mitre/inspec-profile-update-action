control 'SV-206826' do
  title 'The Voice Video Session Manager must be configured to disable non-essential capabilities.'
  desc 'It is detrimental for voice video session managers to provide, or enable by default, functionality exceeding requirements or mission objectives. These unnecessary capabilities or services are often overlooked and therefore may remain unsecured. They increase the risk to the platform by providing additional attack vectors. Voice video session managers are capable of providing a wide variety of functions and services. Some of the functions and services, provided by default, may not be necessary to support essential organizational operations (e.g., key missions, functions).'
  desc 'check', 'Verify the Voice Video Session Manager is configured to disable non-essential capabilities.

If the Voice Video Session Manager is not configured to disable non-essential capabilities, this is a finding.'
  desc 'fix', 'Configure the Voice Video Session Manager to be configured to disable non-essential capabilities.'
  impact 0.5
  ref 'DPMS Target Voice Video Session Management'
  tag check_id: 'C-7081r364667_chk'
  tag severity: 'medium'
  tag gid: 'V-206826'
  tag rid: 'SV-206826r508661_rule'
  tag stig_id: 'SRG-NET-000131-VVSM-00048'
  tag gtitle: 'SRG-NET-000131'
  tag fix_id: 'F-7081r364668_fix'
  tag 'documentable'
  tag legacy: ['V-62087', 'SV-76577']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
