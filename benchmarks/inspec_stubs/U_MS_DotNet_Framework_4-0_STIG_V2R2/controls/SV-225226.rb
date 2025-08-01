control 'SV-225226' do
  title 'Encryption keys used for the .NET Strong Name Membership Condition must be protected.'
  desc "The Strong Name Membership condition requires that member assemblies be defined with Strong Names.  A strong name consists of the assembly's identity, simple text name, version number, and culture information (if provided) — plus a public key and a digital signature.  If assemblies do not have a strong name assigned, the assembly cannot be unique and the author of the code cannot be uniquely identified.  In order to create the strong name, the developer must use a cryptographic key pair to sign the assembly.  If the developer does not protect the key, the key can be stolen and used to sign any application, including malware applications.  This could adversely affect application integrity and confidentiality."
  desc 'check', "If the application is a COTS product, the requirement is Not Applicable (NA).

Caspol.exe is a Microsoft tool used for working with .Net policy.  Use caspol.exe to list the code groups and any publisher membership conditions.

The location of the caspol utility is dependent upon the system architecture of the system running .Net. 

For 32 bit systems, caspol.exe is located at %SYSTEMROOT%\\Microsoft.NET\\Framework\\v4.0.30319.
 
For 64 bit systems, caspol.exe is located at %SYSTEMROOT%\\Microsoft.NET\\Framework64\\v4.0.30319.  

Example:

cd %SYSTEMROOT%\\Microsoft.NET\\Framework\\v4.0.30319

To check code groups, run the following command:

caspol.exe -all -lg

Sample response:
Microsoft (R) .NET Framework CasPol 4.0.30319.1

Security is ON
Execution checking is ON
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

An assembly will satisfy the StrongName Membership Condition if its metadata contains the strongly identifying data associated with the specified strong name. At the least, this means it has been digitally signed with the private key associated with the public key recorded in the policy.

The presence of the encryption key values in the StrongName field indicates the use of StrongName Membership Condition. 

If a Strong Name Membership Condition is assigned to a non-default Code Group the private key must be adequately protected by the software developer or the entity responsible for signing the assemblies. 

Ask the Systems Programmer how the private keys are protected. 

Private keys are simply values stored as strings of data.  Keys can be stored in files on the file system or in a centralized data repository. 

Adequate protection methods include, but are not limited to:

 - utilizing centralized key management;
 - using strict file permissions to limit access; and
 - tying strong pass phrases to the key.

If the private key used to sign the assembly is not adequately protected, this is a finding."
  desc 'fix', 'Ask the Systems Programmer how the private keys used to sign the assembly are protected. 

Private keys are simply values stored as strings of data.  Keys can be stored in files on the file system or in a centralized data repository. 

Adequate protection methods include, but are not limited to:

 - utilizing centralized key management;
 - using strict file permissions to limit access; and
 - tying strong pass phrases to the key.

The private key(s) used to sign the assembly must be protected.  Utilize centralized key management or strict file permissions along with strong pass phrases and/or other well established industry practices for managing and controlling access to private keys.'
  impact 0.5
  ref 'DPMS Target Microsoft DotNet Framework 4-0'
  tag check_id: 'C-26925r467993_chk'
  tag severity: 'medium'
  tag gid: 'V-225226'
  tag rid: 'SV-225226r615940_rule'
  tag stig_id: 'APPNET0052'
  tag gtitle: 'SRG-APP-000176'
  tag fix_id: 'F-26913r467994_fix'
  tag 'documentable'
  tag legacy: ['SV-7450', 'V-7067']
  tag cci: ['CCI-000186']
  tag nist: ['IA-5 (2) (a) (1)']
end
