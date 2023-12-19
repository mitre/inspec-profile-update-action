control 'SV-225258' do
  title 'The Windows 2012 / 2012 R2 system must use an anti-virus program.'
  desc 'Malicious software can establish a base on individual desktops and servers. Employing an automated mechanism to detect this type of software will aid in elimination of the software from the operating system.'
  desc 'check', 'Verify an anti-virus solution is installed on the system. The anti-virus solution may be bundled with an approved host-based security solution.

If there is no anti-virus solution installed on the system, this is a finding.'
  desc 'fix', 'Install an anti-virus solution on the system.'
  impact 0.7
  ref 'DPMS Target Microsoft Windows Server 2012-2012 R2 MS'
  tag check_id: 'C-26957r471116_chk'
  tag severity: 'high'
  tag gid: 'V-225258'
  tag rid: 'SV-225258r569185_rule'
  tag stig_id: 'WN12-00-000100'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-26945r471117_fix'
  tag 'documentable'
  tag legacy: ['SV-52103', 'V-1074']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
