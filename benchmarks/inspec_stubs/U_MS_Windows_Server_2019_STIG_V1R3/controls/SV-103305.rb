control 'SV-103305' do
  title 'Windows Server 2019 must use an anti-virus program.'
  desc 'Malicious software can establish a base on individual desktops and servers. Employing an automated mechanism to detect this type of software will aid in elimination of the software from the operating system.'
  desc 'check', 'Verify an anti-virus solution is installed on the system. The anti-virus solution may be bundled with an approved host-based security solution.

If there is no anti-virus solution installed on the system, this is a finding.'
  desc 'fix', 'Install an anti-virus solution on the system.'
  impact 0.7
  ref 'DPMS Target Windows 2019'
  tag check_id: 'C-92535r1_chk'
  tag severity: 'high'
  tag gid: 'V-93217'
  tag rid: 'SV-103305r1_rule'
  tag stig_id: 'WN19-00-000110'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-99463r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
