control 'SV-223332' do
  title 'File extensions must be enabled to match file types in Excel.'
  desc "This policy setting controls how Excel loads file types that do not match their extension. Excel can load files with extensions that do not match the files' type. For example, if a comma-separated values (CSV) file named example.csv is renamed example.xls (or any other file extension supported by Excel 2003 and earlier only), Excel can properly load it as a CSV file.

If you enable this policy setting, you can choose from three options for working with files that have non-matching extensions:
- Allow different - Excel opens the files properly without warning users that the files have non-matching extensions. If users subsequently edit and save the files, Excel preserves both the true, underlying file format and the incorrect file extension.
- Allow different, but warn - Excel opens the files properly, but warns users about the file type mismatch. This option is the default configuration in Excel.
- Always match file type - Excel does not open any files that have non-matching extensions.

If this policy setting is disabled or not configured or if users attempt to open files with the wrong extension, Excel opens the file and displays a warning that the file type is not what Excel expected."
  desc 'check', 'Verify the policy value for User Configuration >> Administrative Templates >> Microsoft Excel 2016 >> Excel Options >> Security >> Force file extension to match file type is set to "Always match file type".

Use the Windows Registry Editor to navigate to the following key:

HKCU\\software\\policies\\microsoft\\office\\16.0\\excel\\security

If value for extensionhardening is REG_DWORD = 2, this is not a finding.'
  desc 'fix', 'Set policy value for User Configuration >> Administrative Templates >> Microsoft Excel 2016 >> Excel Options >> Security >> Force file extension to match file type to "Enabled" and select the option "Always match file type".'
  impact 0.5
  ref 'DPMS Target Microsoft Office 365 ProPlus'
  tag check_id: 'C-25005r822363_chk'
  tag severity: 'medium'
  tag gid: 'V-223332'
  tag rid: 'SV-223332r879887_rule'
  tag stig_id: 'O365-EX-000023'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-24993r822364_fix'
  tag 'documentable'
  tag legacy: ['SV-108843', 'V-99739']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
