control 'SV-214924' do
  title 'The macOS system must use a DoD antivirus program.'
  desc 'An approved antivirus product must be installed and configured to run.

Malicious software can establish a base on individual desktops and servers. Employing an automated mechanism to detect this type of software will aid in elimination of the software from the operating system.'
  desc 'check', 'Ask the System Administrator (SA) or Information System Security Officer (ISSO) if an approved antivirus solution is loaded on the system. The antivirus solution may be bundled with an approved host-based security solution.

If there is no local antivirus solution installed on the system, this is a finding.'
  desc 'fix', 'Install an approved antivirus solution onto the system.'
  impact 0.7
  ref 'DPMS Target Apple OS X 10.13'
  tag check_id: 'C-16124r397344_chk'
  tag severity: 'high'
  tag gid: 'V-214924'
  tag rid: 'SV-214924r609363_rule'
  tag stig_id: 'AOSX-13-001465'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-16122r397345_fix'
  tag 'documentable'
  tag legacy: ['SV-96443', 'V-81729']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
