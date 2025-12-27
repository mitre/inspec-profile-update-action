control 'SV-225232' do
  title '.Net applications that invoke NetFx40_LegacySecurityPolicy must apply previous versions of .NET STIG guidance.'
  desc 'CAS policy is .NET runtime version-specific.  In .NET Framework version 4, CAS policy is disabled by default however; it can be re-enabled by using the NetFx40_LegacySecurityPolicy setting on a per application basis. Caspol.exe is provided by Microsoft to set security policy on .Net applications prior to version 4.0. This requirement does not apply to the caspol.exe assembly or other assemblies provided with the Windows OS or the Windows Secure Host Baseline (SHB).

When invoking the NetFx40_LegacySecurityPolicy setting in .NET 4, earlier versions of the .NET Framework CAS policy will become active therefore previous .NET STIG guidance that applies to the reactivated versions must also be applied. 

Failure to apply applicable versions of STIG guidance can result in the loss of system confidentiality, integrity or availability.'
  desc 'check', 'Open Windows explorer and search for all *.exe.config files.  This requirement does not apply to the caspol.exe assembly or other assemblies provided with the Windows OS or the Windows Secure Host Baseline (SHB).

To find relevant files, you can run the FINDSTR command from an elevated (admin) command prompt: 
FINDSTR /i /s "NetFx40_LegacySecurityPolicy" c:\\*.exe.config 
This command will search all ."exe.config" files on the c: drive partition for the "LegacySecurityPolicy" setting. Repeat the command for each drive partition on the system.


If the .NET application configuration file utilizes the legacy policy element and .NET STIG guidance that covers these legacy versions has not been applied, this is a finding.'
  desc 'fix', 'Apply the .NET Framework Security Checklist for .Net versions 1 through 3.5 when utilizing the NetFx40_LegacySecurityPolicy setting.'
  impact 0.3
  ref 'DPMS Target Microsoft DotNet Framework 4-0'
  tag check_id: 'C-26931r468011_chk'
  tag severity: 'low'
  tag gid: 'V-225232'
  tag rid: 'SV-225232r615940_rule'
  tag stig_id: 'APPNET0064'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-26919r468012_fix'
  tag 'documentable'
  tag legacy: ['SV-40979', 'V-30937']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
