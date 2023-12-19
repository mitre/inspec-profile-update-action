control 'SV-48424' do
  title 'PKU2U authentication using online identities must be prevented.'
  desc 'PKU2U is a peer-to-peer authentication protocol.   This setting prevents online identities from authenticating to domain-joined systems.  Authentication will be centrally managed with Windows user accounts.'
  desc 'check', 'Analyze the system using the Security Configuration and Analysis snap-in.  (See "Performing Analysis with the Security Configuration and Analysis Snap-in" in the STIG Overview document.)
Expand the Security Configuration and Analysis tree view.
Navigate to Local Policies -> Security Options.

If the value for "Network Security: Allow PKU2U authentication requests to this computer to use online identities" is not set to "Disabled", this is a finding.

The policy referenced configures the following registry value:

Registry Hive: HKEY_LOCAL_MACHINE
Subkey: \\System\\CurrentControlSet\\Control\\LSA\\pku2u\\

Value Name: AllowOnlineID

Type: REG_DWORD
Value: 0'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> "Network Security: Allow PKU2U authentication requests to this computer to use online identities" to "Disabled".'
  impact 0.5
  ref 'DPMS Target Windows 8'
  tag check_id: 'C-45093r2_chk'
  tag severity: 'medium'
  tag gid: 'V-21953'
  tag rid: 'SV-48424r2_rule'
  tag stig_id: 'WN08-SO-000063'
  tag gtitle: 'PKU2U Online Identities Authentication'
  tag fix_id: 'F-41555r1_fix'
  tag 'documentable'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
