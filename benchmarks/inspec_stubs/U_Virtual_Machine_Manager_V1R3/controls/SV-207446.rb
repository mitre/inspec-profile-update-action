control 'SV-207446' do
  title 'The VMM must prevent all software from executing at higher privilege levels than users executing the software.'
  desc 'In certain situations, guest VMs, applications, and programs need to execute with elevated privileges to perform required functions. However, if the privileges required for execution are at a higher level than the privileges assigned to VMM users invoking such applications/programs, those users are indirectly provided with greater privileges than assigned by organizations.

Some guest VMs, applications, programs, and processes are required to operate at a higher privilege level and therefore should be excluded from this restriction after review.'
  desc 'check', 'Verify the VMM prevents all software from executing at higher privilege levels than users executing the software.

If it does not, this is a finding.'
  desc 'fix', 'Configure the VMM to prevent all software from executing at higher privilege levels than users executing the software.'
  impact 0.5
  ref 'DPMS Target Virtual Machine Manager'
  tag check_id: 'C-7703r365748_chk'
  tag severity: 'medium'
  tag gid: 'V-207446'
  tag rid: 'SV-207446r854619_rule'
  tag stig_id: 'SRG-OS-000326-VMM-001160'
  tag gtitle: 'SRG-OS-000326'
  tag fix_id: 'F-7703r365749_fix'
  tag 'documentable'
  tag legacy: ['SV-71353', 'V-57093']
  tag cci: ['CCI-002233']
  tag nist: ['AC-6 (8)']
end
