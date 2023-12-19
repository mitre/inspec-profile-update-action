control 'SV-254200' do
  title 'Nutanix AOS must not have the rsh-server package installed.'
  desc 'It is detrimental for operating systems to provide, or install by default, functionality exceeding requirements or mission objectives. These unnecessary capabilities or services are often overlooked and therefore may remain unsecured. They increase the risk to the platform by providing additional attack vectors.

Operating systems are capable of providing a wide variety of functions and services. Some of the functions and services, provided by default, may not be necessary to support essential organizational operations (e.g., key missions, functions).

Examples of nonessential capabilities include, but are not limited to, games, software packages, tools, and demonstration software, not related to requirements or providing a wide array of functionality not required for every mission, but which cannot be disabled.

'
  desc 'check', 'Confirm Nutanix AOS is configured to disable nonessential capabilities.

$ sudo yum list installed rsh-server

If the rsh-server package is installed, this is a finding.'
  desc 'fix', 'Remove any finding identified by running the correlating command:

$ sudo yum remove rsh-server'
  impact 0.5
  ref 'DPMS Target Nutanix AOS 5.20.x OS'
  tag check_id: 'C-57685r846686_chk'
  tag severity: 'medium'
  tag gid: 'V-254200'
  tag rid: 'SV-254200r846688_rule'
  tag stig_id: 'NUTX-OS-001130'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-57636r846687_fix'
  tag satisfies: ['SRG-OS-000095-GPOS-00049', 'SRG-OS-000074-GPOS-00042']
  tag 'documentable'
  tag cci: ['CCI-000197', 'CCI-000381']
  tag nist: ['IA-5 (1) (c)', 'CM-7 a']
end
