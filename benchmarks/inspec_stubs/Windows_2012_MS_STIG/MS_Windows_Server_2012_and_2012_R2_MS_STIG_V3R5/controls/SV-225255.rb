control 'SV-225255' do
  title 'The operating system must employ a deny-all, permit-by-exception policy to allow the execution of authorized software programs.'
  desc 'Utilizing a whitelist provides a configuration management method for allowing the execution of only authorized software. Using only authorized software decreases risk by limiting the number of potential vulnerabilities.

The organization must identify authorized software programs and only permit execution of authorized software. The process used to identify software programs that are authorized to execute on organizational information systems is commonly referred to as whitelisting.'
  desc 'check', 'This is applicable to unclassified systems; for other systems this is NA.

Verify the operating system employs a deny-all, permit-by-exception policy to allow the execution of authorized software programs.

If an application whitelisting program is not in use on the system, this is a finding.

Configuration of whitelisting applications will vary by the program.

AppLocker is a whitelisting application built into Windows Server 2012.  A deny-by-default implementation is initiated by enabling any AppLocker rules within a category, only allowing what is specified by defined rules.

If AppLocker is used, perform the following to view the configuration of AppLocker:
Open PowerShell.

If the AppLocker PowerShell module has not been previously imported, execute the following first:
Import-Module AppLocker

Execute the following command, substituting [c:\\temp\\file.xml] with a location and file name appropriate for the system:
Get-AppLockerPolicy -Effective -XML > c:\\temp\\file.xml

This will produce an xml file with the effective settings that can be viewed in a browser or opened in a program such as Excel for review.

Implementation guidance for AppLocker is available in the NSA paper "Application Whitelisting using Microsoft AppLocker" at the following link:

https://www.iad.gov/iad/library/ia-guidance/tech-briefs/application-whitelisting-using-microsoft-applocker.cfm'
  desc 'fix', 'Configure an application whitelisting program to employ a deny-all, permit-by-exception policy to allow the execution of authorized software programs.

Configuration of whitelisting applications will vary by the program.  AppLocker is a whitelisting application built into Windows Server 2012.

If AppLocker is used, it is configured through group policy in Computer Configuration >> Windows Settings >> Security Settings >> Application Control Policies >> AppLocker.

Implementation guidance for AppLocker is available in the NSA paper "Application Whitelisting using Microsoft AppLocker" at the following link:

https://www.iad.gov/iad/library/ia-guidance/tech-briefs/application-whitelisting-using-microsoft-applocker.cfm'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2012-2012 R2 MS'
  tag check_id: 'C-26954r471107_chk'
  tag severity: 'medium'
  tag gid: 'V-225255'
  tag rid: 'SV-225255r852179_rule'
  tag stig_id: 'WN12-00-000018'
  tag gtitle: 'SRG-OS-000370-GPOS-00155'
  tag fix_id: 'F-26942r471108_fix'
  tag 'documentable'
  tag legacy: ['SV-72047', 'V-57637']
  tag cci: ['CCI-001774']
  tag nist: ['CM-7 (5) (b)']
end
