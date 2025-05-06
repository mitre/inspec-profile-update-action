control 'SV-216140' do
  title 'The system must disable TCP reverse IP source routing.'
  desc 'If enabled, reverse IP source routing would allow an attacker to more easily complete a three-way TCP handshake and spoof new connections.'
  desc 'check', 'Determine if TCP reverse IP source routing is disabled. 

# ipadm show-prop -p _rev_src_routes -co current tcp

If the output of this command is not "0", this is a finding.'
  desc 'fix', 'The Network Management profile is required.

Disable reverse source routing.

# pfexec ipadm set-prop -p _rev_src_routes=0 tcp'
  impact 0.3
  ref 'DPMS Target Solaris 11 X86'
  tag check_id: 'C-17378r372802_chk'
  tag severity: 'low'
  tag gid: 'V-216140'
  tag rid: 'SV-216140r603268_rule'
  tag stig_id: 'SOL-11.1-050100'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-17376r372803_fix'
  tag 'documentable'
  tag legacy: ['V-48201', 'SV-61073']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
