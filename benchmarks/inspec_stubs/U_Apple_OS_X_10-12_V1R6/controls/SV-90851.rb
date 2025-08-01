control 'SV-90851' do
  title 'The OS X system must use a DoD anti-virus program.'
  desc 'An approved anti-virus product must be installed and configured to run.

Malicious software can establish a base on individual desktops and servers. Employing an automated mechanism to detect this type of software will aid in elimination of the software from the operating system.'
  desc 'check', 'Ask the System Administrator (SA) or Information System Security Officer (ISSO) if an approved anti-virus solution is loaded on the system. The anti-virus solution may be bundled with an approved host-based security solution.

If there is no local anti-virus solution installed on the system, this is a finding.'
  desc 'fix', 'Install an approved anti-virus solution onto the system.'
  impact 0.7
  ref 'DPMS Target Mac OS 10.12 Workstation'
  tag check_id: 'C-75849r1_chk'
  tag severity: 'high'
  tag gid: 'V-76163'
  tag rid: 'SV-90851r1_rule'
  tag stig_id: 'AOSX-12-001465'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-82801r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
