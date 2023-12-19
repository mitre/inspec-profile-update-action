control 'SV-224860' do
  title 'FTP servers must be configured to prevent anonymous logons.'
  desc 'The FTP service allows remote users to access shared files and directories. Allowing anonymous FTP connections makes user auditing difficult.

Using accounts that have administrator privileges to log on to FTP risks that the userid and password will be captured on the network and give administrator access to an unauthorized user.'
  desc 'check', 'If FTP is not installed on the system, this is NA.

Open "Internet Information Services (IIS) Manager".

Select the server.

Double-click "FTP Authentication".

If the "Anonymous Authentication" status is "Enabled", this is a finding.'
  desc 'fix', 'Configure the FTP service to prevent anonymous logons.

Open "Internet Information Services (IIS) Manager".

Select the server.

Double-click "FTP Authentication".

Select "Anonymous Authentication".

Select "Disabled" under "Actions".'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2016'
  tag check_id: 'C-26551r465482_chk'
  tag severity: 'medium'
  tag gid: 'V-224860'
  tag rid: 'SV-224860r569186_rule'
  tag stig_id: 'WN16-00-000430'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-26539r465483_fix'
  tag 'documentable'
  tag legacy: ['SV-87955', 'V-73303']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
