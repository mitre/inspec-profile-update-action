control 'SV-203782' do
  title 'The operating system must not allow an unattended or automatic logon to the system.'
  desc 'Failure to restrict system access to authenticated users negatively impacts operating system security.'
  desc 'check', 'If the operating system provides a public access service, such as a kiosk, this is not applicable. Verify the operating system does not allow an unattended or automatic logon to the system. If it does, this is a finding. Automatic logon as an authorized user allows access to any user with physical access to the operating system.'
  desc 'fix', 'If the operating system provides a public access service, such as a kiosk, this is not applicable. Configure the operating system to not allow an unattended or automatic logon to the system. Automatic logon as an authorized user allows access to any user with physical access to the operating system.'
  impact 0.5
  ref 'DPMS Target General Purpose Operating System'
  tag check_id: 'C-3907r375737_chk'
  tag severity: 'medium'
  tag gid: 'V-203782'
  tag rid: 'SV-203782r388482_rule'
  tag stig_id: 'SRG-OS-000480-GPOS-00229'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-3907r375738_fix'
  tag 'documentable'
  tag legacy: ['V-56587', 'SV-70847']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
