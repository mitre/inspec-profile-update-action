control 'SV-25252' do
  title 'The system must not have unnecessary features installed.'
  desc 'Windows includes additional features available for installation.  The majority of these are unnecessary and may also increase the attack surface of the system.'
  desc 'check', 'Perform the following to verify installed Features:

Open Control Panel.
Select "Programs and Features".
Select "Turn Windows features on or off".

Features currently prohibited:
Games
Windows Media Center (under Media Features)
SimpleTCP Services
Telnet (Client or Server)
TFTP Client

If any of the listed features is selected, this is a finding.'
  desc 'fix', 'Uninstall any prohibited features listed in the manual check.

Open Control Panel.
Select “Programs and Features”.
Select “Turn Windows features on or off”.

Features currently prohibited:  
Games
Windows Media Center (under Media Features)
SimpleTCP Services
Telnet (Client or Server)
TFTP Client'
  impact 0.5
  ref 'DPMS Target Windows 7'
  tag check_id: 'C-60801r1_chk'
  tag severity: 'medium'
  tag gid: 'V-16006'
  tag rid: 'SV-25252r2_rule'
  tag gtitle: 'Unnecessary Features Installed'
  tag fix_id: 'F-65533r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
