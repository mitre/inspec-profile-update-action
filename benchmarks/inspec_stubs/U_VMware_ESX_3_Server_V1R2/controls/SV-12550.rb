control 'SV-12550' do
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
  desc 'fix', 'Remove the network analysis tool binary from the system.  Consult vendor documentation for removing packaged software, or remove the binary directly.

Procedure:
# rm <binary>'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-8008r2_chk'
  tag severity: 'medium'
  tag gid: 'V-12049'
  tag rid: 'SV-12550r2_rule'
  tag stig_id: 'GEN003865'
  tag gtitle: 'GEN003865'
  tag fix_id: 'F-11302r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'DCPA-1'
  tag cci: ['CCI-000305']
  tag nist: ['CM-7 (2)']
end
