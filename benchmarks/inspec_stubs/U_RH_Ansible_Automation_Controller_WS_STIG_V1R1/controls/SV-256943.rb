control 'SV-256943' do
  title 'The Automation Controller must generate the appropriate log records.'
  desc "Automation Controller's web server must log all details related to user sessions in support of troubleshooting, debugging, and forensic analysis.

Without a data logging feature, the organization loses an important auditing and analysis tool for event investigations.

"
  desc 'check', 'For each Automation Controller host, determine whether the web server is logging all content related to user sessions.

Log in to Automation Controller as an administrator and navigate to console Settings >> System >> Miscellaneous System.

Verify the following settings:

Enable Activity Stream = On

Enable Activity Stream for Inventory Sync = On

Organization Admins Can Manage Users and Teams = On

All Users Visible to Organization Admins = On

If the configuration settings are not as above, this is a finding.'
  desc 'fix', 'As a System Administrator, for each Automation Controller host, navigate to console Settings >> System >> Miscellaneous System.

Click "Edit".

Set the following:
Enable Activity Stream = On

Enable Activity Stream for Inventory Sync = On

Organization Admins Can Manage Users and Teams = On

All Users Visible to Organization Admins = On

Click "Save".'
  impact 0.5
  ref 'DPMS Target Red Hat Ansible Automation Controller Web Server'
  tag check_id: 'C-60618r902341_chk'
  tag severity: 'medium'
  tag gid: 'V-256943'
  tag rid: 'SV-256943r903546_rule'
  tag stig_id: 'APWS-AT-000090'
  tag gtitle: 'SRG-APP-000016-WSR-000005'
  tag fix_id: 'F-60560r903520_fix'
  tag satisfies: ['SRG-APP-000016-WSR-000005', 'SRG-APP-000095-WSR-000056', 'SRG-APP-000096-WSR-000057', 'SRG-APP-000097-WSR-000058', 'SRG-APP-000098-WSR-000059', 'SRG-APP-000098-WSR-000060', 'SRG-APP-000099-WSR-000061', 'SRG-APP-000100-WSR-000064']
  tag 'documentable'
  tag cci: ['CCI-000067', 'CCI-000130', 'CCI-000131', 'CCI-000132', 'CCI-000133', 'CCI-000134', 'CCI-001487']
  tag nist: ['AC-17 (1)', 'AU-3 a', 'AU-3 b', 'AU-3 c', 'AU-3 d', 'AU-3 e', 'AU-3 f']
end
