control 'SV-243485' do
  title 'Selective Authentication must be enabled on outgoing forest trusts.'
  desc 'Enabling Selective Authentication on outbound Active Directory (AD) forest trusts significantly strengthens access control by requiring explicit authorization (through the Allowed to Authenticate permission) on resources in the trusting forest.  When Selective Authentication is not enabled, less secure resource access permissions (such as those that specify Authenticated Users) might permit unauthorized access.'
  desc 'check', 'Open "Active Directory Domains and Trusts".  (Available from various menus or run "domain.msc".)
Right click the domain name in the left pane and select "Properties".
Select the "Trusts" tab.
For each outgoing forest trust, right-click the trust item and select "Properties".
Select the "Authentication" tab.

If the "Selective Authentication" option is not selected on every outgoing forest trust, this is a finding.'
  desc 'fix', 'Enable Selective Authentication on outgoing forest trust.   
Open "Active Directory Domains and Trusts".  (Available from various menus or run "domain.msc".)
Right click the domain name in the left pane and select "Properties".
Select the "Trusts" tab.
For each outgoing forest trust, right-click the trust item and select "Properties". 
Select the "Authentication" tab.  
Select the "Selective Authentication" option.
(It may be necessary to configure the "Allowed to Authenticate" permission on resources in the trusting domain.)'
  impact 0.5
  ref 'DPMS Target Active Directory Domain'
  tag check_id: 'C-46760r723488_chk'
  tag severity: 'medium'
  tag gid: 'V-243485'
  tag rid: 'SV-243485r723490_rule'
  tag stig_id: 'AD.0200'
  tag gtitle: 'SRG-OS-000080'
  tag fix_id: 'F-46717r723489_fix'
  tag 'documentable'
  tag legacy: ['V-8540', 'SV-9037']
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
