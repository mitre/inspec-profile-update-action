control 'SV-81463' do
  title 'Access to Tanium logs on each endpoint must be restricted by permissions.'
  desc 'For the Tanium Client software to run without impact from external negligent or malicious changes, the permissions on the Tanium log files and their directory must be restricted.

Tanium is deployed with a Client Hardening Solution. This solution, when applied, will ensure directory permissions are in place.'
  desc 'check', 'Using a web browser on a system that has connectivity to the Tanium Server, access the Tanium Server web user interface (UI) and log on with CAC.

On the Dashboard, select "Client Hardening Tool".

Select the "Set Client Directory Permissions".

Tanium will parse the script and return a row for "Restricted" and a row for "Not Restricted", with their respective client counts.

If the "Not Restricted" row shows a client count of more than "0", this is a finding.'
  desc 'fix', 'Using a web browser on a system that has connectivity to the Tanium Server, access the Tanium Server web user interface (UI) and log on with CAC.

On the Dashboard, select "Client Hardening Tool".

Select the "Set Client Directory Permissions".

Tanium will parse the script and return a row for "Restricted" and a row for "Not Restricted", with their respective client counts.

Click on the "Not Restricted" row and right-click.

Select "Deploy Action".

In the "Deploy Action" dialog box, the package "Client Service Hardening - Set SYSTEM only permissions on Tanium Client directory" will be selected. 

The clients which have their Tanium Client directory "Not Restricted" will be displayed in the bottom window.

Click on "Target & Schedule".

Choose a schedule to deploy the hardening.

Click on "Finish".

Verify settings and click on "Confirm".'
  impact 0.5
  ref 'DPMS Target Tanium 6.5'
  tag check_id: 'C-67609r1_chk'
  tag severity: 'medium'
  tag gid: 'V-66973'
  tag rid: 'SV-81463r1_rule'
  tag stig_id: 'TANS-CL-000002'
  tag gtitle: 'SRG-APP-000119'
  tag fix_id: 'F-73073r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000163']
  tag nist: ['AU-9 a']
end
