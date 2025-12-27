control 'SV-224828' do
  title 'Systems must be maintained at a supported servicing level.'
  desc 'Systems at unsupported servicing levels will not receive security updates for new vulnerabilities, which leave them subject to exploitation. Systems must be maintained at a servicing level supported by the vendor with new security updates.'
  desc 'check', 'Open "Command Prompt".

Enter "winver.exe".

If the "About Windows" dialog box does not display "Microsoft Windows Server Version 1607 (Build 14393.xxx)" or greater, this is a finding.

Preview versions must not be used in a production environment.'
  desc 'fix', 'Update the system to a Version 1607 (Build 14393.xxx) or greater.'
  impact 0.7
  ref 'DPMS Target Windows Server 2016'
  tag check_id: 'C-26519r465386_chk'
  tag severity: 'high'
  tag gid: 'V-224828'
  tag rid: 'SV-224828r569186_rule'
  tag stig_id: 'WN16-00-000110'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-26507r465387_fix'
  tag 'documentable'
  tag legacy: ['SV-87891', 'V-73239']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
