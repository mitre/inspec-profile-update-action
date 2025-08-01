control 'SV-226237' do
  title 'Systems must be maintained at a supported service pack level.'
  desc 'Systems at unsupported service packs or releases will not receive security updates for new vulnerabilities, which leave them subject to exploitation.  Systems must be maintained at a service pack level supported by the vendor with new security updates.'
  desc 'check', 'Run "winver.exe". 

If the "About Windows" dialog box does not display 
"Microsoft Windows Server 
Version 6.2 (Build 9200)"
or greater, this is a finding. 
      
No preview versions will be used in a production environment. 

Unsupported Service Packs/Releases:
Windows 2012 - any release candidates or versions prior to the initial release.'
  desc 'fix', 'Update the system to a supported release or service pack level.'
  impact 0.7
  ref 'DPMS Target Windows Server 2012-2012 R2 Domain Controller'
  tag check_id: 'C-27939r476555_chk'
  tag severity: 'high'
  tag gid: 'V-226237'
  tag rid: 'SV-226237r794611_rule'
  tag stig_id: 'WN12-GE-000001'
  tag gtitle: 'SRG-OS-000191-GPOS-00080'
  tag fix_id: 'F-27927r476556_fix'
  tag 'documentable'
  tag legacy: ['V-1073', 'SV-53189']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
