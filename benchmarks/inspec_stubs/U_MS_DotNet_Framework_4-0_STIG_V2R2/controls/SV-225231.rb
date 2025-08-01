control 'SV-225231' do
  title '.NET must be configured to validate strong names on full-trust assemblies.'
  desc 'The "bypassTrustedAppStrongNames" setting specifies whether the bypass feature that avoids validating strong names for full-trust assemblies is enabled. By default the bypass feature is enabled in .Net 4, therefore strong names are not validated for correctness when the assembly/program is loaded. Not validating strong names provides a faster application load time but at the expense of performing certificate validation. 

Full trust assemblies are .Net applications launched from the local host. Strong names are digital signatures tied to .Net applications/assemblies.  .Net 4 considers applications installed locally to be fully trusted by default and grants these applications full permissions to access host resources. 

The bypass feature applies to any assembly signed with a strong name and having the following characteristics:

    Fully trusted without the StrongName evidence (for example, has MyComputer zone evidence).

    Loaded into a fully trusted AppDomain.

    Loaded from a location under the ApplicationBase property of that AppDomain.

    Not delay-signed.

Not validating the certificates used to sign strong name assemblies will provide a faster application load time, but falsely assumes that signatures used to sign the application are to be implicitly trusted.  Not validating strong name certificates introduces an integrity risk to the system.'
  desc 'check', 'If there is documented ISSO risk acceptance for development systems, this is not a finding.
For 32 bit production systems: 
Use regedit to examine the “HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\.NETFramework” key.  
On 64-bit production systems:
Use regedit to examine both the “HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\.NETFramework” and “HKEY_LOCAL_MACHINE\\SOFTWARE\\Wow6432Node\\Microsoft\\.NETFramework” keys.
If the "AllowStrongNameBypass" value does not exist, or if the “DWORD” value is set to “1”, this is a finding.

Documentation must include a complete list of installed .Net applications, application versions, and acknowledgement that ISSO trusts each installed application.

If application versions installed on the system do not match approval documentation, this is a finding.'
  desc 'fix', 'For 32 bit production systems: 
Set “HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\.NETFramework\\AllowStrongNameBypass" to a “DWORD” value of “0”.
On 64-bit production systems:
Set “HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\.NETFramework\\ AllowStrongNameBypass” and “HKEY_LOCAL_MACHINE\\SOFTWARE\\Wow6432Node\\Microsoft\\.NETFramework\\ AllowStrongNameBypass” to a “DWORD” value of “0”.
Or, obtain documented ISSO risk acceptance for each .Net application installed on the system. 

Approval documentation will include complete list of all installed .Net applications, application versions, and acknowledgement of ISSO trust of each installed application.'
  impact 0.5
  ref 'DPMS Target Microsoft DotNet Framework 4-0'
  tag check_id: 'C-26930r468008_chk'
  tag severity: 'medium'
  tag gid: 'V-225231'
  tag rid: 'SV-225231r615940_rule'
  tag stig_id: 'APPNET0063'
  tag gtitle: 'SRG-APP-000175'
  tag fix_id: 'F-26918r468009_fix'
  tag 'documentable'
  tag legacy: ['SV-40977', 'V-30935']
  tag cci: ['CCI-000185']
  tag nist: ['IA-5 (2) (b) (1)']
end
