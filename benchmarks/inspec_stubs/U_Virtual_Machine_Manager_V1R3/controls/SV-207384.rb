control 'SV-207384' do
  title 'The VMM must be configured to disable non-essential capabilities.'
  desc 'It is detrimental for VMMs to provide, or install by default, functionality exceeding requirements or mission objectives. These unnecessary capabilities or services are often overlooked and therefore may remain unsecured. They increase the risk to the platform by providing additional attack vectors.

VMMs are capable of providing a wide variety of functions and services. Some of the functions and services, provided by default, may not be necessary to support essential organizational operations (e.g., key missions, functions).'
  desc 'check', 'Verify the VMM is configured to disable non-essential capabilities.

If it is not, this is a finding.'
  desc 'fix', 'Configure the VMM to disable non-essential capabilities.'
  impact 0.5
  ref 'DPMS Target Virtual Machine Manager'
  tag check_id: 'C-7641r365562_chk'
  tag severity: 'medium'
  tag gid: 'V-207384'
  tag rid: 'SV-207384r378841_rule'
  tag stig_id: 'SRG-OS-000095-VMM-000480'
  tag gtitle: 'SRG-OS-000095'
  tag fix_id: 'F-7641r365563_fix'
  tag 'documentable'
  tag legacy: ['SV-71219', 'V-56959']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
