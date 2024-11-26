control 'SV-220094' do
  title 'Network analysis tools must not be installed.'
  desc 'Network analysis tools allow for the capture of network traffic visible to the system.'
  desc 'check', 'Determine if any network analysis tools are installed.

Procedure:
# find / -name ethereal
# find / -name wireshark
# find / -name tshark
# find / -name netcat
# find / -name tcpdump
# find / -name snoop

If any network analysis tools are found, this is a finding.'
  desc 'fix', 'Remove the network analysis tool binary from the system. The snoop binary is part of the SUNWrcmdc package, which may also be removed if none of its components are required.

Procedure:
# rm <binary>
# pkgrm SUNWrcmdc'
  impact 0.5
  ref 'DPMS Target Solaris 10 X86'
  tag check_id: 'C-21803r489850_chk'
  tag severity: 'medium'
  tag gid: 'V-220094'
  tag rid: 'SV-220094r603266_rule'
  tag stig_id: 'GEN003865'
  tag gtitle: 'SRG-OS-000095'
  tag fix_id: 'F-21802r489851_fix'
  tag 'documentable'
  tag legacy: ['V-12049', 'SV-40811']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
