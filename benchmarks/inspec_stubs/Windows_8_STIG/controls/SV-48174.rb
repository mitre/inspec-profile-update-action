control 'SV-48174' do
  title 'User Account Control must automatically deny elevation requests for standard users.'
  desc 'User Account Control (UAC) is a security mechanism for limiting the elevation of privileges, including administrative accounts, unless authorized. Denying elevation requests from standard user accounts requires tasks that need elevation to be initiated by accounts with administrative privileges.  This prevents privileged account credentials from being cached with standard user profile information to help mitigate credential theft.'
  desc 'check', 'Analyze the system using the Security Configuration and Analysis snap-in. (See "Performing Analysis with the Security Configuration and Analysis Snap-in" in the STIG Overview document.)
Expand the Security Configuration and Analysis tree view.
Navigate to Local Policies >> Security Options.

If the value for "User Account Control: Behavior of the elevation prompt for standard users" is not set to "Automatically deny elevation requests", this is a finding.

The policy referenced configures the following registry value:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\

Value Name: ConsentPromptBehaviorUser

Value Type: REG_DWORD
Value: 0x00000000 (0)'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options >> "User Account Control: Behavior of the elevation prompt for standard users" to "Automatically deny elevation requests".'
  impact 0.5
  ref 'DPMS Target Windows 8'
  tag check_id: 'C-72727r2_chk'
  tag severity: 'medium'
  tag gid: 'V-14236'
  tag rid: 'SV-48174r3_rule'
  tag stig_id: 'WN08-SO-000079'
  tag gtitle: 'UAC - User Elevation Prompt'
  tag fix_id: 'F-78891r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002038']
  tag nist: ['IA-11']
end
