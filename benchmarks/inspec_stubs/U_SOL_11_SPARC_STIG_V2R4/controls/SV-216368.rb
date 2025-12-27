control 'SV-216368' do
  title 'The system must disable directed broadcast packet forwarding.'
  desc 'This parameter must be disabled to reduce the risk of denial of service attacks.'
  desc 'check', 'Determine if directed broadcast packet forwarding is disabled.

# ipadm show-prop -p _forward_directed_broadcasts -co current ip

If the output of this command is not "0", this is a finding.'
  desc 'fix', 'The Network Management profile is required.

Disable directed broadcast packet forwarding.

# pfexec ipadm set-prop -p _forward_directed_broadcasts=0 ip'
  impact 0.3
  ref 'DPMS Target Solaris 11 SPARC'
  tag check_id: 'C-17604r371192_chk'
  tag severity: 'low'
  tag gid: 'V-216368'
  tag rid: 'SV-216368r603267_rule'
  tag stig_id: 'SOL-11.1-050010'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-17602r371193_fix'
  tag 'documentable'
  tag legacy: ['V-48165', 'SV-61037']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
