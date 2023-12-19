control 'SV-253797' do
  title 'The application must employ a deny-all, permit-by-exception (allowlist) policy to allow the execution of authorized software programs.'
  desc 'Using an allowlist provides a configuration management method for allowing the execution of only authorized software. Using only authorized software decreases risk by limiting the number of potential vulnerabilities.

The organization must identify authorized software programs and permit execution of authorized software. The process used to identify software programs that are authorized to execute on organizational information systems is commonly referred to as allowlisting.

Verification of allowlisted software can occur either prior to execution or at system startup.

This requirement applies to configuration management applications or similar types of applications designed to manage system processes and configurations (e.g., HBSS and software wrappers).'
  desc 'check', 'If Enforce is not used to manage allowlisting, this check is not applicable.

1. Using a web browser on a system that has connectivity to the Tanium application, access the Tanium application web user interface (UI) and log on with multifactor authentication.

2. Click "Modules" on the top navigation banner.
 
3. Select the "Enforce" module.

4. Click the three dots next to the "Enforce" header.

5. Click "Enforcements".

6. Verify an enforcement exists for allowlisting by looking for "AppLocker" in the "Policy" column.

7. Click each enforcement for allowlisting Policy type and verify the enforcement is applied to all applicable machines.

If an AppLocker Policy is not applied to all applicable machines, this is a finding.'
  desc 'fix', 'If Enforce is not used to manage allowlisting, no fix is needed.

1. Using a web browser on a system that has connectivity to the Tanium application, access the Tanium application web UI and log on with multifactor authentication.

2. Click "Modules" on the top navigation banner.
 
3. Click "Enforce".

4. Expand the left menu.

5. From the Enforce menu, go to Policy Configurations. 

6. Click "Action" and then "Create".

7. In the "General Information" section:

- Enter a Name and Description for the policy.
- Select AppLocker from the Policy Type options. Policy types can be filtered by operating system (All, Windows, Mac, Linux).
 
8. (Optional) If there is already a policy of this type, that policy can serve as the starting point for a new policy. Select the policy in the "Starting Point" pull-down menu.
 
If requirements for this policy are missing, that information is displayed in the "Configuration Status" section. Refer to Configure Endpoint Encryption settings for BitLocker requirements.

9. In the "Settings" section:
 
- Enter Support URL (optional).
- Import Rules from XML (optional).
- Select Rule Type (at least 1).

10. For each Rule Type:

- Choose: Blocking. 
- Click "Create" under "Block" section. 

11. Click "Create".'
  impact 0.5
  ref 'DPMS Target Tanium 7.x'
  tag check_id: 'C-57249r842417_chk'
  tag severity: 'medium'
  tag gid: 'V-253797'
  tag rid: 'SV-253797r850221_rule'
  tag stig_id: 'TANS-00-001405'
  tag gtitle: 'SRG-APP-000386'
  tag fix_id: 'F-57200r842418_fix'
  tag 'documentable'
  tag cci: ['CCI-001774']
  tag nist: ['CM-7 (5) (b)']
end
