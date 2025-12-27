control 'SV-254247' do
  title 'Windows Server 2022 must be maintained at a supported servicing level.'
  desc 'Systems at unsupported servicing levels will not receive security updates for new vulnerabilities, which leave them subject to exploitation. Systems must be maintained at a servicing level supported by the vendor with new security updates.'
  desc 'check', 'Open "Command Prompt".

Enter "winver.exe".

If the "About Windows" dialog box does not display "Microsoft Windows Server Version 21H1 (Build 20348.xxx)" or greater, this is a finding.

Preview versions must not be used in a production environment.'
  desc 'fix', 'Update the system to a Version 21H2 (Build 20348.xxx) or greater.'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2022'
  tag check_id: 'C-57732r848555_chk'
  tag severity: 'medium'
  tag gid: 'V-254247'
  tag rid: 'SV-254247r848557_rule'
  tag stig_id: 'WN22-00-000100'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-57683r848556_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
