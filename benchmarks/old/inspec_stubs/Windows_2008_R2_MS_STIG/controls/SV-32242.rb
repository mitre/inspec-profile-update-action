control 'SV-32242' do
  title 'Systems must be maintained at a supported version of an operating system.'
  desc 'Systems at unsupported versions or releases of an operating system will not receive security updates for new vulnerabilities, which leaves them subject to exploitation. Systems must be maintained at a version of the operating system supported by the vendor with new security updates.'
  desc 'check', 'Support for Windows 2008/2008 R2 ended 14 January 2020. After this date, systems must have Windows 2012 or greater installed.

Run "winver.exe".

If the "About Windows" dialog box does not display:
"Microsoft Windows
Version 6.3 (Build 9600)"
or greater, this is a finding.'
  desc 'fix', 'Update the system to a version of the operating system supported by the vendor.

Support for Windows 2008/2008 R2 ended 14 January 2020. After this date, systems must have Windows 2012 or greater installed.'
  impact 0.7
  ref 'DPMS Target Windows 2008 R2'
  tag check_id: 'C-94143r4_chk'
  tag severity: 'high'
  tag gid: 'V-1073'
  tag rid: 'SV-32242r5_rule'
  tag gtitle: 'Unsupported Service Packs'
  tag fix_id: 'F-30098r4_fix'
  tag 'documentable'
  tag third_party_tools: 'HK'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
