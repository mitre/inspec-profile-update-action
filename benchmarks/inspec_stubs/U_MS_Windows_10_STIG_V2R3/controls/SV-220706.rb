control 'SV-220706' do
  title 'Windows 10 systems must be maintained at a supported servicing level.'
  desc 'Windows 10 is maintained by Microsoft at servicing levels for specific periods of time to support Windows as a Service. Systems at unsupported servicing levels or releases will not receive security updates for new vulnerabilities which leaves them subject to exploitation.

New versions with feature updates are planned to be released on a semi-annual basis with an estimated support timeframe of 18 to 30 months depending on the release. Support for previously released versions has been extended for Enterprise editions.

A separate servicing branch intended for special purpose systems is the Long-Term Servicing Channel (LTSC, formerly Branch - LTSB) which will receive security updates for 10 years but excludes feature updates.'
  desc 'check', 'Run "winver.exe".

If the "About Windows" dialog box does not display:

"Microsoft Windows Version 1909 (OS Build 18363.0)"

or greater, this is a finding.

Note: Microsoft has extended support for previous versions providing critical and important updates for Windows 10 Enterprise.

Microsoft scheduled end of support dates for current Semi-Annual Channel versions:

v1909 - 10 May 2022
v2004 - 14 December 2021
v20H2 – 9 May 2023

No preview versions will be used in a production environment.

Special-purpose systems using the Long-Term Servicing Branch\\Channel (LTSC\\B) may be at the following versions, which is not a finding:

v1507 (Build 10240)
v1607 (Build 14393)
v1809 (Build 17763)'
  desc 'fix', 'Update systems on the Semi-Annual Channel to "Microsoft Windows Version 1909 (OS Build 18363.0)" or greater.

It is recommended systems be upgraded to the most recently released version.

Special-purpose systems using the Long-Term Servicing Branch\\Channel (LTSC\\B) may be at the following versions:

v1507 (Build 10240)
v1607 (Build 14393)
v1809 (Build 17763)'
  impact 0.7
  ref 'DPMS Target Windows 10'
  tag check_id: 'C-22421r646210_chk'
  tag severity: 'high'
  tag gid: 'V-220706'
  tag rid: 'SV-220706r646212_rule'
  tag stig_id: 'WN10-00-000040'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-22410r646211_fix'
  tag 'documentable'
  tag legacy: ['V-63349', 'SV-77839']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
