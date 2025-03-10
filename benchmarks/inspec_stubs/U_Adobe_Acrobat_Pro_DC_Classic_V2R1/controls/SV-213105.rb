control 'SV-213105' do
  title 'Unsupported versions of Adobe Acrobat Pro DC Classic must be uninstalled.'
  desc 'Adobe has ended support for Acrobat Pro DC Classic track and is no longer providing patches or security updates for this product. Organizations (including any contractor to the organization) are required to promptly remove Acrobat Pro DC Classic track versions as they are no longer supported by the vendor.'
  desc 'check', 'Review the applications that are installed on the system. 

Verify Adobe Acrobat Pro DC Classic is not installed.

If Adobe Acrobat Pro Classic is installed, this is a finding.'
  desc 'fix', 'Remove/uninstall the Adobe Acrobat Pro DC application. Replace with a supported Acrobat version if required.'
  impact 0.7
  ref 'DPMS Target Adobe Acrobat Professional DC Classic Track'
  tag check_id: 'C-14343r548545_chk'
  tag severity: 'high'
  tag gid: 'V-213105'
  tag rid: 'SV-213105r557504_rule'
  tag stig_id: 'AADC-CL-001075'
  tag gtitle: 'SRG-APP-000456'
  tag fix_id: 'F-14341r548540_fix'
  tag 'documentable'
  tag legacy: ['SV-94839', 'V-80135']
  tag cci: ['CCI-002605']
  tag nist: ['SI-2 c']
end
