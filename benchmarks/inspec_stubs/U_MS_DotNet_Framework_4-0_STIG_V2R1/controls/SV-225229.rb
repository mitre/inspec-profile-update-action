control 'SV-225229' do
  title '.Net Framework versions installed on the system must be supported.'
  desc 'Unsupported software introduces risks and violates DoD policy.  Applications utilizing unsupported versions of .NET introduce substantial risk to the host, network, and the enclave by virtue of the fact they leverage an architecture that is no longer updated by the vendor.  This introduces potential application integrity, availability, or confidentiality issues.'
  desc 'check', 'Determine which versions of the .NET Framework are installed by opening the directory %systemroot%\\Microsoft.NET.

The folder named "%systemroot%\\Microsoft.NET\\Framework" contains .NET files for 32 bit systems.  The folder named "%systemroot%\\Microsoft.NET\\Framework64" contains .NET files for 64 bit systems. 64 bit systems will have both the 32 bit and the 64 bit folders while 32 bit systems do not have a Framework64 folder.

Within each of the aforementioned folders are the individual folder names that contain the corresponding versions of the .NET Framework:

v4.0.30319
v3.5
v3.0
v2.0.50727
v1.1.4322
v1.0.3705

Search for all the Mscorlib.dll files in the %systemroot%\\Microsoft.NET\\Framework folder and the %systemroot%\\Microsoft.NET\\Framework64 folder if the folder exists. Click on each of the files, view properties, and click version tab to determine the version installed.  If there is no Mscorlib.dll, there is no installed version of .Net Framework in that directory.

More specific information on determining versions of .Net Framework installed can be found at the following link. http://support.microsoft.com/kb/318785

Verify extended support is available for the installed versions of .Net Framework.

Verify the .Net Framework support dates with Microsoft Product Lifecycle Search link.
http://support.microsoft.com/lifecycle/search/?sort=PN&alpha=.NET+Framework

Beginning with .NET 3.5 SP1, the .NET Framework is considered a Component of the Windows OS. Components follow the Support Lifecycle policy of their parent product or platform.
 
If any versions of the .Net Framework are installed and support is no longer available, this is a finding.'
  desc 'fix', 'Remove unsupported versions of the .NET Framework and upgrade legacy applications that utilize unsupported versions of the .NET framework.'
  impact 0.5
  ref 'DPMS Target Microsoft DotNet Framework 4-0'
  tag check_id: 'C-26928r468002_chk'
  tag severity: 'medium'
  tag gid: 'V-225229'
  tag rid: 'SV-225229r615940_rule'
  tag stig_id: 'APPNET0061'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-26916r468003_fix'
  tag 'documentable'
  tag legacy: ['SV-55642', 'V-18395']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
