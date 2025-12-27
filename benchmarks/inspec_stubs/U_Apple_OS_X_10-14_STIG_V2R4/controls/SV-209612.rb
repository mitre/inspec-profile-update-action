control 'SV-209612' do
  title 'The macOS system must use an approved antivirus program.'
  desc 'An approved antivirus product must be installed and configured to run.

Malicious software can establish a base on individual desktops and servers. Employing an automated mechanism to detect this type of software will aid in elimination of the software from the operating system.'
  desc 'check', 'Ask the System Administrator (SA) or Information System Security Officer (ISSO) if an approved antivirus solution is loaded on the system. The antivirus solution may be bundled with an approved host-based security solution.

If there is no local antivirus solution installed on the system, this is a finding.'
  desc 'fix', 'Install an approved antivirus solution onto the system.'
  impact 0.7
  ref 'DPMS Target Apple OS X 10.14'
  tag check_id: 'C-9863r282318_chk'
  tag severity: 'high'
  tag gid: 'V-209612'
  tag rid: 'SV-209612r610285_rule'
  tag stig_id: 'AOSX-14-002070'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-9863r282319_fix'
  tag 'documentable'
  tag legacy: ['SV-104727', 'V-95543']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
