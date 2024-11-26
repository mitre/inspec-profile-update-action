control 'SV-29470' do
  title 'The Windows 2008 system must use an anti-virus program.'
  desc 'Malicious software can establish a base on individual desktops and servers. Employing an automated mechanism to detect this type of software will aid in elimination of the software from the operating system.'
  desc 'check', 'Verify an anti-virus solution is installed on the system. The anti-virus solution may be bundled with an approved host-based security solution.

If there is no anti-virus solution installed on the system, this is a finding.'
  desc 'fix', 'Install an anti-virus solution on the system.'
  impact 0.7
  ref 'DPMS Target Windows 2008'
  tag check_id: 'C-75971r1_chk'
  tag severity: 'high'
  tag gid: 'V-1074'
  tag rid: 'SV-29470r5_rule'
  tag stig_id: 'WIN00-000100'
  tag gtitle: 'WIN00-000100'
  tag fix_id: 'F-82923r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
