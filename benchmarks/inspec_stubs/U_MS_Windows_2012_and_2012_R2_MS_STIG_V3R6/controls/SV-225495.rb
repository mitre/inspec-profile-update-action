control 'SV-225495' do
  title 'Named pipes that can be accessed anonymously must be configured to contain no values on member servers.'
  desc 'Named pipes that can be accessed anonymously provide the potential for gaining unauthorized system access.  Pipes are internal system communications processes.  They are identified internally by ID numbers that vary between systems.  To make access to these processes easier, these pipes are given names that do not vary between systems.  This setting controls which of these pipes anonymous users may access.'
  desc 'check', "If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \\System\\CurrentControlSet\\Services\\LanManServer\\Parameters\\

Value Name: NullSessionPipes

Value Type: REG_MULTI_SZ
Value: (blank)

Legitimate applications may add entries to this registry value. If an application requires these entries to function properly and is documented with the ISSO, this would not be a finding.  Documentation must contain supporting information from the vendor's instructions."
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> "Network access: Named pipes that can be accessed anonymously" to be defined but containing no entries (blank).'
  impact 0.7
  ref 'DPMS Target Microsoft Windows Server 2012-2012 R2 MS'
  tag check_id: 'C-27194r471827_chk'
  tag severity: 'high'
  tag gid: 'V-225495'
  tag rid: 'SV-225495r569185_rule'
  tag stig_id: 'WN12-SO-000055-MS'
  tag gtitle: 'SRG-OS-000138-GPOS-00069'
  tag fix_id: 'F-27182r471828_fix'
  tag 'documentable'
  tag legacy: ['V-3338', 'SV-51497']
  tag cci: ['CCI-001090']
  tag nist: ['SC-4']
end
