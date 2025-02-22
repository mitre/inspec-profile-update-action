control 'SV-6274' do
  title 'Unauthorized named pipes are accessible with anonymous credentials.'
  desc 'This is a Category 1 finding because the potential for gaining unauthorized system access.  Pipes are internal system communications processes.  They are identified internally by ID numbers that vary between systems.  To make access to these processes easier, these pipes are given names that do not vary between systems.  This setting controls which of these pipes anonymous users may access.'
  desc 'check', "Analyze the system using the Security Configuration and Analysis snap-in.
Expand the Security Configuration and Analysis tree view.
Navigate to Local Policies -> Security Options.

If the value for “Network access: Named pipes that can be accessed anonymously” contains entries besides “COMNAP, COMNODE, SQL\\QUERY, SPOOLSS, LLSRPC, browser”, then this is a finding.

The policy referenced configures the following registry value:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \\System\\CurrentControlSet\\Services\\LanManServer\\Parameters\\

Value Name:  NullSessionPipes

Value Type:  REG_MULTI_SZ
Value:  As defined in the policy above
 
Note: Legitimate applications may add entries to this registry value. If an application requires these entries to function properly and is documented with the IAO this would not be a finding.  Documentation should contain supporting information from the vendor's instructions.

Note:  Windows XP 64-Bit is based on Windows 2003.  An XP 64-bit system will include the following by default:  COMNAP, COMNODE, SQL\\QUERY, SPOOLSS, NETLOGON, LSARPC, SAMR, BROWSER"
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> “Network access: Named pipes that can be accessed anonymously” as defined in the Check section.'
  impact 0.7
  ref 'DPMS Target Windows XP'
  tag check_id: 'C-154r1_chk'
  tag severity: 'high'
  tag gid: 'V-3338'
  tag rid: 'SV-6274r1_rule'
  tag gtitle: 'Anonymous Access to Named Pipes'
  tag fix_id: 'F-28868r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
end
