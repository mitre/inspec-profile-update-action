control 'SV-46359' do
  title 'The File System Object component must be disabled.'
  desc 'Some Component Object Model (COM) components are not required for most applications and should be removed if possible.  Most notably, consider disabling the File System Object component; however, this will also remove the Dictionary object. Be aware some programs may require this component (e.g., Commerce Server), so it is highly recommended this be tested completely before implementing on the production web server.'
  desc 'check', '1. Locate the HKEY_CLASSES_ROOT\\CLSID\\{0D43FE01-F093-11CF-8940-00A0C9054228} registry key.  If the key exist, the File System Object component is enabled.

2. If the File System Object component is enabled and is not required for operations, this is a finding.

NOTE: If the File System Object component is required for operations and has supporting documentation signed by the ISSO, this is not a finding.'
  desc 'fix', 'Run the following command, with adminstrator priviledges, to unregister the File System Object:  regsvr32 scrrun.dll /u.

Note: Make sure the Administrators group owns and has full permissions to the registry value HKCR\\TypeLib\\{420B2830-E718-11CF-893D-00A0C9054228}\\1.0\\0\\win32 before trying to unregister the dll.  Without the Administrators group owning and having full control of this key, the unregister command will error.'
  impact 0.5
  ref 'DPMS Target IIS Installation 7'
  tag check_id: 'C-32934r8_chk'
  tag severity: 'medium'
  tag gid: 'V-13700'
  tag rid: 'SV-46359r4_rule'
  tag stig_id: 'WA000-WI100 IIS7'
  tag gtitle: 'WA000-WI100'
  tag fix_id: 'F-29076r2_fix'
  tag 'documentable'
  tag responsibility: 'Web Administrator'
end
