control 'SV-224861' do
  title 'FTP servers must be configured to prevent access to the system drive.'
  desc 'The FTP service allows remote users to access shared files and directories that could provide access to system resources and compromise the system, especially if the user can gain access to the root directory of the boot drive.'
  desc 'check', 'If FTP is not installed on the system, this is NA.

Open "Internet Information Services (IIS) Manager".

Select "Sites" under the server name.

For any sites with a Binding that lists FTP, right-click the site and select "Explore".

If the site is not defined to a specific folder for shared FTP resources, this is a finding.

If the site includes any system areas such as root of the drive, Program Files, or Windows directories, this is a finding.'
  desc 'fix', 'Configure the FTP sites to allow access only to specific FTP shared resources. Do not allow access to other areas of the system.'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2016'
  tag check_id: 'C-26552r465485_chk'
  tag severity: 'medium'
  tag gid: 'V-224861'
  tag rid: 'SV-224861r569186_rule'
  tag stig_id: 'WN16-00-000440'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-26540r465486_fix'
  tag 'documentable'
  tag legacy: ['SV-87957', 'V-73305']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
