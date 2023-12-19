control 'SV-237437' do
  title 'The default Builtin\\Administrators group must be removed from the SCOM Administrators Role Group.'
  desc 'SCOM servers with default well-known operating system groups defined the SCOM Administrators Global Group may allow a local administrator access to privileged SCOM access.'
  desc 'check', 'Review the SCOM Administrators Global Group and verify that the Built-in\\Administrators Group is not a member.

If the Built-in\\Administrators group is a member, this is a finding.'
  desc 'fix', 'Remove the Built-in\\Administrators group from the SCOM Administrators Role Group.'
  impact 0.5
  ref 'DPMS Target Microsoft SCOM'
  tag check_id: 'C-40656r643955_chk'
  tag severity: 'medium'
  tag gid: 'V-237437'
  tag rid: 'SV-237437r643957_rule'
  tag stig_id: 'SCOM-IA-000003'
  tag gtitle: 'SRG-APP-000080-NDM-000345'
  tag fix_id: 'F-40619r643956_fix'
  tag 'documentable'
  tag cci: ['CCI-002041']
  tag nist: ['IA-5 (1) (f)']
end
