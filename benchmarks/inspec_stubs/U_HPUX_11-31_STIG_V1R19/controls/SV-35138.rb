control 'SV-35138' do
  title 'Network analysis tools must not be installed.'
  desc 'Network analysis tools allow for the capture of network traffic visible to the system.'
  desc 'check', 'Determine if any network analysis tools are installed. Search for the binary:
# find / -type f -name ethereal | xargs -n1 ls -lL
# find / -type f -name wireshark | xargs -n1 ls -lL
# find / -type f -name tshark | xargs -n1 ls -lL 
# find / -type f -name netcat | xargs -n1 ls -lL
# find / -type f -name tcpdump | xargs -n1 ls -lL
# find / -type f -name snoop | xargs -n1 ls -lL
# find / -type f -name nettl | xargs -n1 ls -lL

If any network analysis tools are found, this is a finding.'
  desc 'fix', 'Remove the network analysis tool binary from the system. Consult vendor documentation for removing packaged software, or remove the binary directly via the following example:
# rm -i <binary>'
  impact 0.5
  ref 'DPMS Target HP-UX 11.31'
  tag check_id: 'C-36544r2_chk'
  tag severity: 'medium'
  tag gid: 'V-12049'
  tag rid: 'SV-35138r2_rule'
  tag stig_id: 'GEN003865'
  tag gtitle: 'GEN003865'
  tag fix_id: 'F-31909r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000305']
  tag nist: ['CM-7 (2)']
end
