control 'SV-79145' do
  title 'A production OHS Installation must prohibit the installation of a compiler.'
  desc 'The presence of a compiler on a production server facilitates the malicious user’s task of creating custom versions of programs and installing Trojan Horses or viruses.  For example, the attacker’s code can be uploaded and compiled on the server under attack.'
  desc 'check', '1. Ask the System Administrator if a compiler is installed on the system.

2. If it is, this is a finding.'
  desc 'fix', 'Ask the System Administrator to remove any compilers installed on the system.'
  impact 0.5
  ref 'DPMS Target Oracle HTTP Server (OHS) 12.1.x'
  tag check_id: 'C-65397r1_chk'
  tag severity: 'medium'
  tag gid: 'V-64655'
  tag rid: 'SV-79145r1_rule'
  tag stig_id: 'OH12-1X-000208'
  tag gtitle: 'SRG-APP-000516-WSR-000174'
  tag fix_id: 'F-70585r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
