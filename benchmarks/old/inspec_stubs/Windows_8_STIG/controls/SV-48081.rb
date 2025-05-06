control 'SV-48081' do
  title 'The system must be configured to prevent the storage of the LAN Manager hash of passwords.'
  desc 'The LAN Manager hash uses a weak encryption algorithm and there are several tools available that use this hash to retrieve account passwords.  This setting controls whether or not a LAN Manager hash of the password is stored in the SAM the next time the password is changed.'
  desc 'check', 'Analyze the system using the Security Configuration and Analysis snap-in.  (See "Performing Analysis with the Security Configuration and Analysis Snap-in" in the STIG Overview document.)
Expand the Security Configuration and Analysis tree view.
Navigate to Local Policies -> Security Options.

If the value for "Network security: Do not store LAN Manager hash value on next password change" is not set to "Enabled", this is a finding.

The policy referenced configures the following registry value:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \\System\\CurrentControlSet\\Control\\Lsa\\

Value Name: NoLMHash

Value Type: REG_DWORD
Value: 1'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> "Network security: Do not store LAN Manager hash value on next password change" to "Enabled".'
  impact 0.7
  ref 'DPMS Target Windows 8'
  tag check_id: 'C-44820r1_chk'
  tag severity: 'high'
  tag gid: 'V-3379'
  tag rid: 'SV-48081r1_rule'
  tag stig_id: 'WN08-SO-000065'
  tag gtitle: 'LAN Manager Hash stored'
  tag fix_id: 'F-41219r1_fix'
  tag 'documentable'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000196']
  tag nist: ['IA-5 (1) (c)']
end
