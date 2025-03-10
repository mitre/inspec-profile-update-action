control 'SV-93763' do
  title 'An unsupported Adobe Acrobat Pro version must not be installed.'
  desc 'Failure to install the most current Adobe Acrobat Pro version leaves a system vulnerable to exploitation. Current versions correct known security and system vulnerabilities. 

If the Adobe Acrobat Pro installation is not at the most current version and patch level, this is a Category 1 finding since new vulnerabilities will not be patched.

Adobe Acrobat Pro XI is End of Life. Reference the following URL: http://www.adobe.com/support/products/enterprise/eol/. Click on "Adobe enterprise products and technical support periods".'
  desc 'check', 'For Windows systems:

Select Settings >> System >> Apps and Features

For UNIX/Linux systems: 

Utilize the relevant UNIX/Linux OS commands to identify installed software.

If Adobe Acrobat XI Pro is installed, review security plan documentation for risk acceptance of temporary operation while Acrobat XI Pro is in the process of being replaced or upgraded.

If Adobe Acrobat XI Pro is installed on the system with no documented risk acceptance, or if high-risk vulnerabilities associated with Acrobat XI Pro become known or publicized, this is a finding.'
  desc 'fix', 'Upgrade to latest version of Adobe Acrobat or uninstall software.'
  impact 0.7
  ref 'DPMS Target Adobe Acrobat Pro XI'
  tag check_id: 'C-78647r3_chk'
  tag severity: 'high'
  tag gid: 'V-79057'
  tag rid: 'SV-93763r1_rule'
  tag stig_id: 'ADBP-XI-005000'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-85809r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
end
