control 'SV-216142' do
  title 'The system must set maximum number of incoming connections to 1024.'
  desc 'This setting controls the maximum number of incoming connections that can be accepted on a TCP port limiting exposure to denial of service attacks.'
  desc 'check', 'Determine if the maximum number of incoming connections is set to 1024.

# ipadm show-prop -p _conn_req_max_q -co current tcp

If the value returned is smaller than "1024", this is a finding. 

In environments where connection numbers are high, such as a busy web server, this value may need to be increased.'
  desc 'fix', 'The Network Management profile is required.

Configure maximum number of incoming connections.

# pfexec ipadm set-prop -p _conn_req_max_q=1024 tcp'
  impact 0.3
  ref 'DPMS Target Solaris 11 X86'
  tag check_id: 'C-17380r372808_chk'
  tag severity: 'low'
  tag gid: 'V-216142'
  tag rid: 'SV-216142r603268_rule'
  tag stig_id: 'SOL-11.1-050120'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-17378r372809_fix'
  tag 'documentable'
  tag legacy: ['V-48211', 'SV-61083']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
