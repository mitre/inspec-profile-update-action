control 'SV-228523' do
  title 'Blogging entries created from inside Office products must be configured for SharePoint only.'
  desc 'The blogging feature in Office products enables users to compose blog entries and post them to their blogs directly from Office, without using any additional software.
By default, users can post blog entries to any compatible blogging service provider, including Windows Live Spaces, Blogger, a SharePoint or Community Server site, and others. Leaving this capability enabled introduces the risk of users posting confidential and FOUO date to non-DoD sites.'
  desc 'check', %q(Verify the policy value for User Configuration >> Administrative Templates >> Microsoft Office 2013 >> Miscellaneous "Control Blogging" is set to "Enabled (Only SharePoint blogs allowed)".

Use the Windows Registry Editor to navigate to the following HKCU\Software\Policies\Microsoft\Office\Common\Blog

If the value 'DisableBlog' is REG_DWORD = 1, this is not a finding.)
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Office 2013 -> Miscellaneous "Control Blogging" to "Enabled (Only SharePoint blogs allowed)".'
  impact 0.5
  ref 'DPMS Target Microsoft Office System 2013'
  tag check_id: 'C-30756r498847_chk'
  tag severity: 'medium'
  tag gid: 'V-228523'
  tag rid: 'SV-228523r508020_rule'
  tag stig_id: 'DTOO212'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-30741r498848_fix'
  tag 'documentable'
  tag legacy: ['V-17581', 'SV-52756']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
