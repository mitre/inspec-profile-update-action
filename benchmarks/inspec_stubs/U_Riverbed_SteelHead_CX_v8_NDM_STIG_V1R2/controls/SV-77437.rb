control 'SV-77437' do
  title 'Riverbed Optimization System (RiOS) must employ automated mechanisms to centrally verify authentication settings.'
  desc 'The use of authentication servers or other centralized management servers for providing centralized authentication services is required for network device management. Maintaining local administrator accounts for daily usage on each network device without centralized management is not scalable or feasible. Without centralized management, it is likely that credentials for some network devices will be forgotten, leading to delays in administration, which itself leads to delays in remediating production problems and in addressing compromises in a timely fashion.'
  desc 'check', 'Verify that RiOS is configured to employ automated mechanisms to centrally verify authentication settings.

Navigate to the device Management Console
Navigate to Configure >> Security >> TACACS+
Verify that "TACACS+ Servers" has at least one server defined

-- or --

Navigate to Configure >> Security >> RADIUS
Verify that "RADIUS Servers" has at least one server defined

If no servers exist in "TACACS+ Servers" or "RADIUS Servers", this is a finding.'
  desc 'fix', 'Configure RiOS to employ automated mechanisms to centrally verify authentication settings.

Navigate to the device Management Console

Navigate to Configure >> Security >> TACACS+
Click "Add a TACACS+ Server"
Set "Hostname or IP Address" to the hostname or IP address of the TACACS+ server
Set "Enabled"
Click "Add"
Click "Set a Global Default Key"
Set the value of "Global Key" to the required value
Set the value of "Confirm Global Key" to the required value
Click "Apply"

Navigate to the top of the web page and click "Save" to save these settings permanently

-- or --

Navigate to Configure >> Security >> RADIUS
Click "Add a RADIUS Server"
Set "Hostname or IP Address" to the hostname or IP address of the RADIUS server
Set the value of "Authentication Port" to the appropriate value
Set the value of "Authentication Type" to "CHAP"
Set "Enabled"
Click "Add"
Click "Set a Global Default Key"
Set the value of "Global Key" to the required value
Set the value of "Confirm Global Key" to the required value
Click "Apply"

Navigate to the top of the web page and click "Save" to save these settings permanently'
  impact 0.5
  ref 'DPMS Target Riverbed SteelHead CX Version 8 NDM'
  tag check_id: 'C-63699r1_chk'
  tag severity: 'medium'
  tag gid: 'V-62947'
  tag rid: 'SV-77437r1_rule'
  tag stig_id: 'RICX-DM-000094'
  tag gtitle: 'SRG-APP-000516-NDM-000338'
  tag fix_id: 'F-68865r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-000372']
  tag nist: ['CM-6 b', 'CM-6 (1)']
end
