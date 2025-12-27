control 'SV-225225' do
  title 'Developer certificates used with the .NET Publisher Membership Condition must be approved by the IAO.'
  desc 'A .Net assembly will satisfy the Publisher Membership Condition if it is signed with a software publisher’s Authenticode X.509v3 digital certificate that can be verified by the Windows operating system as having a chain of trust that leads to a trusted root certificate stored in the user’s certificate store. The  Publisher Membership Condition can be used to identify an organization, developer, vendor, or other entity as the ultimate source of the assembly, even if the code itself was obtained from a third party, such as a mirror site.  Access to system resources, such as file systems or printers, may then be granted to the assembly based on the trust relationship with the identified entity.

Certificates used to sign assemblies so the Publisher Member Condition may be applied must originate from a trusted source.  Using a certificate that is not from a trusted source could potentially violate  system integrity and confidentiality.'
  desc 'check', "Caspol.exe is a Microsoft tool used for working with .Net policy.  Use caspol.exe to list the code groups and any publisher membership conditions.

The location of the caspol utility is dependent upon the system architecture of the system running .Net. 

For 32 bit systems, caspol.exe is located at %SYSTEMROOT%\\Microsoft.NET\\Framework\\v4.0.30319.
 
For 64 bit systems, caspol.exe is located at %SYSTEMROOT%\\Microsoft.NET\\Framework64\\v4.0.30319.  

Example:

cd %SYSTEMROOT%\\Microsoft.NET\\Framework\\v4.0.30319

To check code groups for the machine, run the following command.

caspol.exe -m -lg

Sample Results:
Microsoft (R) .NET Framework CasPol 4.0.30319.1
Copyright (c) Microsoft Corporation.  All rights reserved.

Policy change prompt is ON

Level = Machine

Code Groups:

1.  All code: Nothing
   1.1.  Zone - MyComputer: FullTrust (LevelFinal)
      1.1.1.  StrongName - 002400000480000094000000060200000024000052534131000400000100010007D1FA57C4AED9F0A32E84AA0FAEFD0DE9E8FD6AEC8F87FB03766C834C99921EB23BE79AD9D5DCC1DD9AD236132102900B723CF980957FC4E177108FC607774F29E8320E92EA05ECE4E821C0A5EFE8F1645C4C0C93C1AB99285D622CAA652C1DFAD63D745D6F2DE5F17E5EAF0FC4963D261C8A12436518206DC093344D5AD293: FullTrust
      1.1.2.  StrongName - 00000000000000000400000000000000: FullTrust
   1.2.  Zone - Intranet: LocalIntranet
      1.2.1.  All code: Same site Web
      1.2.2.  All code: Same directory FileIO - 'Read, PathDiscovery'
   1.3.  Zone - Internet: Internet
      1.3.1.  All code: Same site Web
   1.4.  Zone - Untrusted: Nothing
   1.5.  (First Match) Zone - Trusted: Internet
      1.5.1.  All code: Same site Web
   1.6.  Publisher - 30818902818100E47B359ACC061D70C237B572FA276C9854CFABD469DFB74E77D026630BEE2A0C2F8170A823AE69FDEB65704D7FD446DEFEF1F6BA12B6ACBDB1BFA7B9B595AB9A40636467CFF7C73F198B53A9A7CF177F6E7896EBC591DD3003C5992A266C0AD9FBEE4E2A056BE7F7ED154D806F7965F83B0AED616C192C6416CFCB46FC2F5CFD0203010001: FullTrust
Success

Section 1.6 above indicates the presence of a publishers key that meets the Publishers Membership Condition and is also given full trust. 

If the Publisher Membership Condition is used on a non-default Code Group and the use of that publisher's certificate is not documented and approved by the IAO, this is a finding."
  desc 'fix', "Trust must be established when utilizing Publishers Membership Condition.  All publishers' certificates must have documented approvals from the IAO."
  impact 0.5
  ref 'DPMS Target Microsoft DotNet Framework 4-0'
  tag check_id: 'C-26924r467990_chk'
  tag severity: 'medium'
  tag gid: 'V-225225'
  tag rid: 'SV-225225r615940_rule'
  tag stig_id: 'APPNET0048'
  tag gtitle: 'SRG-APP-000175'
  tag fix_id: 'F-26912r467991_fix'
  tag 'documentable'
  tag legacy: ['SV-7446', 'V-7063']
  tag cci: ['CCI-000185']
  tag nist: ['IA-5 (2) (b) (1)']
end
