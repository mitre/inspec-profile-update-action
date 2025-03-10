control 'SV-228526' do
  title 'The ability to run unsecure Office apps must be disabled.'
  desc "Unsecure apps for Office, which are apps that have web page or catalog locations that are not SSL-secured (https://), and/or are not in users' Internet zones may allow data to be transmitted/accessed via clear text to outside sources. By configuring this policy to be disabled, users will be prevented from transmitting/accessing data in a nonsecure manner."
  desc 'check', %q(Verify the policy value for User Configuration >> Administrative Templates >> Microsoft Office 2013 >> Security Settings >> Trust Center >> Trusted Catalogs "Allow Unsecure Apps and Catalogs" is set to "Disabled".

Procedure: Use the Windows Registry Editor to navigate to the following hive: 

HKCU\Software\Policies\Microsoft\Office\15.0\wef\trustedcatalogs

If the value 'requireserververification' is REG_DWORD = 1, this is not a finding.)
  desc 'fix', 'Set the policy value for User Configuration >> Administrative Templates >> Microsoft Office 2013 >> Security Settings >> Trust Center >> Trusted Catalogs "Allow Unsecure Apps and Catalogs" to "Disabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Office System 2013'
  tag check_id: 'C-30759r498856_chk'
  tag severity: 'medium'
  tag gid: 'V-228526'
  tag rid: 'SV-228526r508020_rule'
  tag stig_id: 'DTOO412'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-30744r498857_fix'
  tag 'documentable'
  tag legacy: ['V-40882', 'SV-53214']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
