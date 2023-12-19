control 'SV-234143' do
  title 'The FortiGate firewall must protect the traffic log from unauthorized deletion of local log files and log records.'
  desc 'If audit data were to become compromised, forensic analysis and discovery of the true source of potentially malicious system activity would be impossible to achieve.

To ensure the veracity of audit data, the information system and/or the application must protect audit information from unauthorized modification. This can be achieved through multiple methods, which will depend on system architecture and design. Some commonly employed methods include ensuring log files receive the proper file system permissions and limiting log data locations.

Audit information includes all information (e.g., audit records, audit settings, and audit reports) needed to successfully audit information system activity.

This does not apply to traffic logs generated on behalf of the device itself (management). Traffic logs and Management logs are separate on FortiGate.'
  desc 'check', 'Log in to the FortiGate GUI with an administrator that has no Log and Report access.

1. Open a CLI console, via SSH or available from the GUI.
2. Run the following command:
     $ execute log delete

3. Ensure that the command fails.

If an Administrator without Log and Report privileges can delete locally stored logs, this is a finding.'
  desc 'fix', 'Log in to the FortiGate GUI with Super-Admin privilege.

1. Click System.
2. Click Admin Profiles.
3. Click +Create New (Admin Profile).
4. Assign a meaningful name to the Profile.
5. Set Log and Report access permissions to None.
6. Click OK to save this Profile.

Then, 
1. Click System.
2. Click Administrators.
3. Click the Administrator that is not allowed access to log settings.
4. Assign the Admin Profile that was created above.
5. Click OK to save.

Repeat this process to remove log access for all Administrators without an organizational need to modify log records.'
  impact 0.7
  ref 'DPMS Target Fortinet FortiGate Firewall'
  tag check_id: 'C-37328r611427_chk'
  tag severity: 'high'
  tag gid: 'V-234143'
  tag rid: 'SV-234143r628776_rule'
  tag stig_id: 'FNFG-FW-000060'
  tag gtitle: 'SRG-NET-000100-FW-000023'
  tag fix_id: 'F-37293r611428_fix'
  tag 'documentable'
  tag cci: ['CCI-000164']
  tag nist: ['AU-9 a']
end
