control 'SV-16946' do
  title 'Event log sizes do not meet minimum requirements.'
  desc 'Inadequate log size will cause the log to fill up quickly and require frequent clearing by administrative personnel.'
  desc 'check', 'Vista/2008 - If the following registry values don’t exist or are not configured as specified, then this is a finding:

Registry Hive:  HKEY_LOCAL_MACHINE

Subkey:  Software\\Policies\\Microsoft\\Windows\\EventLog\\Application
Value Name:	 MaxSize
Type:  REG_DWORD
Value:  32768

Subkey:  Software\\Policies\\Microsoft\\Windows\\EventLog\\Security
Value Name:	 MaxSize
Type:  REG_DWORD
Value:  81920

Subkey:  Software\\Policies\\Microsoft\\Windows\\EventLog\\Setup
Value Name:	 MaxSize
Type:  REG_DWORD
Value:  32768

Subkey:  Software\\Policies\\Microsoft\\Windows\\EventLog\\System
Value Name:	 MaxSize
Type:  REG_DWORD
Value:  32768

Documentable: Yes
Documentable Explanation: If the machine is configured to write an event log directly to an audit server, the “Maximum log size” for that log does not have to conform to the requirements above. This should be documented with the IAO.'
  desc 'fix', 'Configure the following policy values as listed below:

Computer Configuration -> Administrative Templates -> Windows Components -> Event Log Service -> 

Application -> “Maximum Log Size (KB)” will be set to “Enabled:32768”
Security -> “Maximum Log Size (KB)” will be set to “Enabled:81920”
Setup -> “Maximum Log Size (KB)” will be set to “Enabled:32768”
System -> “Maximum Log Size (KB)” will be set to “Enabled:32768”'
  impact 0.5
  ref 'DPMS Target Windows Vista'
  tag check_id: 'C-16639r1_chk'
  tag severity: 'medium'
  tag gid: 'V-1118'
  tag rid: 'SV-16946r1_rule'
  tag gtitle: 'Event Log Sizes'
  tag fix_id: 'F-16018r1_fix'
  tag potential_impacts: 'Microsoft recommends that the combined size of all the event logs (including DNS logs, Directory Services logs, and Replication logs on Servers or Domain Controllers) should not exceed 300 megabytes.  Exceeding the recommended value can impact performance.'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-001849']
  tag nist: ['AU-4']
end
