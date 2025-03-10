control 'SV-104511' do
  title 'Symantec ProxySG must employ automated mechanisms to centrally verify authentication settings.'
  desc 'The use of authentication servers or other centralized management servers for providing centralized authentication services is required for network device management. Maintaining local administrator accounts for daily usage on each network device without centralized management is not scalable or feasible. Without centralized management, it is likely that credentials for some network devices will be forgotten, leading to delays in administration, which itself leads to delays in remediating production problems and in addressing compromises in a timely fashion.'
  desc 'check', 'Verify a AAA server is used for access by system administrators as required in DoD.

1. Log on to the Web Management Console.
2. Click Configuration >> Authentication >> RADIUS.
3. Confirm that a RADIUS realm has been configured.
4. Click Configuration >> Policy >> Visual Policy Manager.
5. Click "Launch", select the "Admin Authentication" layer.
6. Confirm the "Action" in each rule references the RADIUS realm in step 3.

If Symantec ProxySG does not employ automated mechanisms to centrally verify authentication settings, this is a finding.'
  desc 'fix', 'Configure the Symantec ProxySG to use a centrally administered AAA server.

1. Log on to the Web Management Console.
2. Click Configuration >> Authentication >> RADIUS.
3. Click "New" then enter a Realm name.
4. Under "Realm configuration" enter the IP address for the primary RADIUS server and modify port (if necessary).
5. Enter a Secret pre-shared key, and enter the same Secret pre-shred key for confirmation, click "OK".
6. Click Radius Servers.
7. Enter an IP address for the Alternate Server and modify port (if necessary).
8. Click "Apply".
9. Click Configuration >> Policy >> Visual Policy Manager.
10. Click "Launch", select the "Admin Authentication" layer.
11. Right-click the "Action" in each rule and click "Set".
12. Click "New", then "Authenticate", and choose the RADIUS realm configured in step 3.
13. Click "File", click "Install Policy on SG Appliance".'
  impact 0.5
  ref 'DPMS Target Symantec ProxySG NDM'
  tag check_id: 'C-93871r1_chk'
  tag severity: 'medium'
  tag gid: 'V-94681'
  tag rid: 'SV-104511r1_rule'
  tag stig_id: 'SYMP-NM-000150'
  tag gtitle: 'SRG-APP-000516-NDM-000338'
  tag fix_id: 'F-100799r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-000372']
  tag nist: ['CM-6 b', 'CM-6 (1)']
end
