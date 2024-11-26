control 'SV-71493' do
  title 'The operating system must prevent all software from executing at higher privilege levels than users executing the software.'
  desc 'In certain situations, software applications/programs need to execute with elevated privileges to perform required functions. However, if the privileges required for execution are at a higher level than the privileges assigned to organizational users invoking such applications/programs, those users are indirectly provided with greater privileges than assigned by the organizations.

Some programs and processes are required to operate at a higher privilege level and therefore should be excluded from the organization-defined software list after review.'
  desc 'check', 'Verify that the operating system prevents all software from executing at higher privilege levels than users executing the software. If it does not, this is a finding.'
  desc 'fix', 'Configure the operating system to prevent all software from executing at higher privilege levels than users executing the software.'
  impact 0.5
  ref 'DPMS Target SRG-OS-GPOS'
  tag check_id: 'C-57839r1_chk'
  tag severity: 'medium'
  tag gid: 'V-57233'
  tag rid: 'SV-71493r1_rule'
  tag stig_id: 'SRG-OS-000326-GPOS-00126'
  tag gtitle: 'SRG-OS-000326-GPOS-00126'
  tag fix_id: 'F-62163r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002233']
  tag nist: ['AC-6 (8)']
end
