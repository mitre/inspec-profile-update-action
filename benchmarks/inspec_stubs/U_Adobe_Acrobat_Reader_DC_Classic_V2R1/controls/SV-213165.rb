control 'SV-213165' do
  title 'Unsupported version of Adobe Acrobat Reader DC Classic must be uninstalled.'
  desc 'Adobe has ended support for Acrobat Reader Classic track and is no longer providing patches or security updates for this product. Organizations (including any contractor to the organization) are required to promptly remove Acrobat Reader Classic track versions as they are no longer supported by the vendor.'
  desc 'check', 'Review the applications that are installed on the system. 

Verify Adobe Acrobat Reader DC Classic is not installed.

If Adobe Acrobat Reader DC Classic is installed, this is a finding.'
  desc 'fix', 'Remove/uninstall the Adobe Acrobat Reader DC application. Replace with a supported Acrobat version if required.'
  impact 0.7
  ref 'DPMS Target Adobe Acrobat Reader DC Classic Track'
  tag check_id: 'C-14401r548542_chk'
  tag severity: 'high'
  tag gid: 'V-213165'
  tag rid: 'SV-213165r557349_rule'
  tag stig_id: 'ARDC-CL-000340'
  tag gtitle: 'SRG-APP-000456'
  tag fix_id: 'F-14399r548543_fix'
  tag 'documentable'
  tag legacy: ['V-65811', 'SV-80301']
  tag cci: ['CCI-002605']
  tag nist: ['SI-2 c']
end
