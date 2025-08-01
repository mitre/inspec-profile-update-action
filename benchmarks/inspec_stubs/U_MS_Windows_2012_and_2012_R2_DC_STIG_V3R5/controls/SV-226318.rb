control 'SV-226318' do
  title 'Named pipes that can be accessed anonymously must be configured with limited values on domain controllers.'
  desc 'Named pipes that can be accessed anonymously provide the potential for gaining unauthorized system access.  Pipes are internal system communications processes.  They are identified internally by ID numbers that vary between systems.  To make access to these processes easier, these pipes are given names that do not vary between systems.  This setting controls which of these pipes anonymous users may access.'
  desc 'check', %q(If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \System\CurrentControlSet\Services\LanManServer\Parameters\

Value Name: NullSessionPipes

Value Type: REG_MULTI_SZ
Value: netlogon, samr, lsarpc

The default configuration of systems promoted to domain controllers may include a blank entry in the first line prior to "netlogon", "samr", and "lsarpc".  This will appear in the registry as a blank entry when viewing the registry key summary; however the value data for "NullSessionPipes" will contain the default entries.

Legitimate applications may add entries to this registry value. If an application requires these entries to function properly and is documented with the ISSO, this would not be a finding. Documentation must contain supporting information from the vendor's instructions.)
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> "Network access: Named pipes that can be accessed anonymously" to only include "netlogon, samr, lsarpc".'
  impact 0.7
  ref 'DPMS Target Microsoft Windows Server 2012-2012 R2 DC'
  tag check_id: 'C-28020r476798_chk'
  tag severity: 'high'
  tag gid: 'V-226318'
  tag rid: 'SV-226318r794545_rule'
  tag stig_id: 'WN12-SO-000055-DC'
  tag gtitle: 'SRG-OS-000138-GPOS-00069'
  tag fix_id: 'F-28008r476799_fix'
  tag 'documentable'
  tag legacy: ['V-3338', 'SV-51138']
  tag cci: ['CCI-001090']
  tag nist: ['SC-4']
end
