control 'SV-71009' do
  title 'The operating system must be configured to disable non-essential capabilities.'
  desc 'It is detrimental for operating systems to provide, or install by default, functionality exceeding requirements or mission objectives. These unnecessary capabilities or services are often overlooked and therefore may remain unsecured. They increase the risk to the platform by providing additional attack vectors.

Operating systems are capable of providing a wide variety of functions and services. Some of the functions and services, provided by default, may not be necessary to support essential organizational operations (e.g., key missions, functions).

Examples of non-essential capabilities include, but are not limited to, games, software packages, tools, and demonstration software, not related to requirements or providing a wide array of functionality not required for every mission, but which cannot be disabled.'
  desc 'check', 'Verify the operating system is configured to disable non-essential capabilities. If it does not, this is a finding.'
  desc 'fix', 'Configure the operating system to disable non-essential capabilities.'
  impact 0.5
  ref 'DPMS Target SRG-OS-GPOS'
  tag check_id: 'C-57319r1_chk'
  tag severity: 'medium'
  tag gid: 'V-56749'
  tag rid: 'SV-71009r1_rule'
  tag stig_id: 'SRG-OS-000095-GPOS-00049'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-61645r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
