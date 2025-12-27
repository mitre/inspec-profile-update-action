control 'SV-254901' do
  title 'Access to Tanium logs on each endpoint must be restricted by permissions.'
  desc 'For the Tanium Client software to run without impact from external negligent or malicious changes, the permissions on the Tanium log files and their directory must be restricted.

Tanium is deployed with a Client Hardening Solution. This solution, when applied, will ensure directory permissions are in place.'
  desc 'check', '1. Using a web browser on a system that has connectivity to the Tanium Application, access the Tanium Application web user interface (UI) and log on with multi-factor authentication.

2. Click "Administration" on the top navigation banner.

3. Under Actions, select "Scheduled Actions".

4. Look for a scheduled action titled "Client Service Hardening - Set SYSTEM only permissions on Tanium Client directory".

If a scheduled action titled "Client Service Hardening - Set SYSTEM only permissions on Tanium Client directory" does not exist, or there is a Scheduled Action contradicting the "Client Service Hardening - Set SYSTEM only permissions on Tanium Client directory" scheduled action, this is a finding.

If the scheduled action exists, select it and if it is not approved (the "Approve" button at the top of the section will be displayed if not approved), this is a finding.'
  desc 'fix', '1. Using a web browser on a system that has connectivity to the Tanium Application, access the Tanium Application web user interface (UI) and log on with multi-factor authentication.

2. Ask the question "Get Tanium Client Directory Permissions from all machines".

Tanium will parse the script and return a row for "Restricted" and a row for "Not Restricted", with their respective client counts.

3. Click the "Not Restricted" row.

4. Select "Deploy Action".

In the "Deploy Action" dialog box, the package "Client Service Hardening - Set SYSTEM only permissions on Tanium Client directory" will be selected.

The clients, which have their Tanium Client directory "Not Restricted" will be displayed in the bottom window.

5. Choose a schedule to deploy the hardening.

6. Under "Targeting Criteria," in the Action Group, select "All Computers" from the drop-down.

7. Click "Deploy Action".

8. Verify settings.

9. Click "Show Client Status Details".'
  impact 0.5
  ref 'DPMS Target Tanium 7.x Application on TanOS'
  tag check_id: 'C-58514r870361_chk'
  tag severity: 'medium'
  tag gid: 'V-254901'
  tag rid: 'SV-254901r870361_rule'
  tag stig_id: 'TANS-AP-000295'
  tag gtitle: 'SRG-APP-000119'
  tag fix_id: 'F-58458r867602_fix'
  tag 'documentable'
  tag cci: ['CCI-000163']
  tag nist: ['AU-9 a']
end
