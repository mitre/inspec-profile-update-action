control 'SV-93245' do
  title 'Process exclusions configured in McAfee MOVE AV On Access Scan Policy must be formally documented by the System Administrator and approved by the ISSO/ISSM.'
  desc 'When scanning for malware, excluding specific file types will increase the risk of a malware-infected file going undetected. By configuring anti-virus software to scan all file types, the scanner has a higher success rate at detecting and eradicating malware. Excluding files, paths, and processes from being scanned expands the potential for malware to be allowed onto the information system. While it is recognized that some file types might need to be excluded for operational reasons and/or because there is protection afforded to those files through a different mechanism, allowing those exclusions should always be vetted, documented, and approved before applying.'
  desc 'check', 'Access the McAfee ePO console.

Select Menu >> Policy >> Policy Catalog and then select "MOVE AntiVirus 4.5.0" from the Product list.

From the Category list, select "On Access Scan".

Select each configured On Access Scan policy.

Under "Exclusions", verify no Process Exclusions have been configured other than the following:

%WINDIR%\\system32\\mssearch.exe
UserProfileManager.exe
%WINDIR%\\system32\\searchindexer.exe
%WINDIR%\\system32\\mssdmn.exe
%WINDIR%\\system32\\winfs\\winfs.exe
%WINDIR%\\system32\\mssfh.exe

If any Process Exclusions are configured and those Process Exclusions have not been formally documented by the System Administrator and approved by the ISSO/ISSM, this is a finding.'
  desc 'fix', 'Access the McAfee ePO console.

Select Menu >> Policy >> Policy Catalog and then select "MOVE AntiVirus 4.5.0" from the Product list.

From the Category list, select "On Access Scan".

Select each configured On Access Scan policy.

Under "Exclusions", remove any Process Exclusions that have been configured other than the following:

%WINDIR%\\system32\\mssearch.exe
UserProfileManager.exe
%WINDIR%\\system32\\searchindexer.exe
%WINDIR%\\system32\\mssdmn.exe
%WINDIR%\\system32\\winfs\\winfs.exe
%WINDIR%\\system32\\mssfh.exe

Click "Save".'
  impact 0.5
  ref 'DPMS Target McAfee MOVE MultiPlatform Client 4.5'
  tag check_id: 'C-78109r1_chk'
  tag severity: 'medium'
  tag gid: 'V-78539'
  tag rid: 'SV-93245r1_rule'
  tag stig_id: 'MV45-OAS-000008'
  tag gtitle: 'MV45-OAS-000008'
  tag fix_id: 'F-85275r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
