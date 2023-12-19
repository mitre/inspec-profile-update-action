control 'SV-33464' do
  title 'Blogging entries created from inside Office products must be configured for Sharepoint only.'
  desc 'The blogging feature in Office products enables users to compose blog entries and post them to their blogs directly from Office, without using any additional software.
By default, users can post blog entries to any compatible blogging service provider, including Windows Live Spaces, Blogger, a SharePoint or Community Server site, and others. If your organization has policies that govern the posting of blog entries, allowing users to access the blogging feature in Office might enable them to violate those policies.'
  desc 'check', 'The policy value for User Configuration -> Administrative Templates -> Microsoft Office 2010 -> Miscellaneous “Control Blogging” must be “Enabled (Only SharePoint blogs allowed)”.

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\Common\\Blog

Criteria: If the value DisableBlog is REG_DWORD = 1, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Office 2010 -> Miscellaneous “Control Blogging” to “Enabled (Only SharePoint blogs allowed)”.'
  impact 0.5
  ref 'DPMS Target Microsoft Office System 2010'
  tag check_id: 'C-33947r1_chk'
  tag severity: 'medium'
  tag gid: 'V-17581'
  tag rid: 'SV-33464r1_rule'
  tag stig_id: 'DTOO212 - Office System'
  tag gtitle: 'DTOO212 - Control Blogging'
  tag fix_id: 'F-29636r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
