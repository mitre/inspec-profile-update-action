control 'SV-32481' do
  title 'Named pipes that can be accessed anonymously will be configured to contain no values.'
  desc 'This is a Category 1 finding due to the potential for gaining unauthorized system access. Pipes are internal system communications processes. They are identified internally by ID numbers that vary between systems. To make access to these processes easier, these pipes are given names that do not vary between systems. This setting controls which of these pipes may be accessed anonymously.'
  desc 'check', "Analyze the system using the Security Configuration and Analysis snap-in. 
Expand the Security Configuration and Analysis tree view.  
Navigate to Local Policies -> Security Options.

If the value for “Network access: Named pipes that can be accessed anonymously” contains any entries, then this is a finding.

The policy referenced configures the following registry value:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \\System\\CurrentControlSet\\Services\\LanManServer\\Parameters\\

Value Name:  NullSessionPipes

Value Type:  REG_MULTI_SZ
Value:  (blank)

Note: Legitimate applications may add entries to this registry value. If an application requires these entries to function properly and is documented with the IAO, this would not be a finding.  Documentation should contain supporting information from the vendor's instructions."
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> “Network access: Named pipes that can be accessed anonymously” to include no entries (blank).'
  impact 0.7
  ref 'DPMS Target Windows 2008 R2'
  tag check_id: 'C-32796r1_chk'
  tag severity: 'high'
  tag gid: 'V-3338'
  tag rid: 'SV-32481r2_rule'
  tag stig_id: '3.063-MS'
  tag gtitle: 'Anonymous Access to Named Pipes'
  tag fix_id: 'F-41053r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-001090']
  tag nist: ['SC-4']
end
