control 'SV-216372' do
  title 'The system must not respond to broadcast ICMP echo requests.'
  desc 'ICMP echo requests can be useful for reconnaissance of systems and for denial of service attacks.'
  desc 'check', 'Determine if ICMP echo requests response is disabled.

# ipadm show-prop -p _respond_to_echo_broadcast -co current ip

If the output of this command is not "0", this is a finding.'
  desc 'fix', 'The Network Management profile is required.

Disable respond to echo broadcast.

# pfexec ipadm set-prop -p _respond_to_echo_broadcast=0 ip'
  impact 0.5
  ref 'DPMS Target Solaris 11 SPARC'
  tag check_id: 'C-17608r371204_chk'
  tag severity: 'medium'
  tag gid: 'V-216372'
  tag rid: 'SV-216372r603267_rule'
  tag stig_id: 'SOL-11.1-050050'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-17606r371205_fix'
  tag 'documentable'
  tag legacy: ['SV-61053', 'V-48181']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
