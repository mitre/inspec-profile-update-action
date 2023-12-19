control 'SV-226079' do
  title 'Windows services that are critical for directory server operation must be configured for automatic startup.'
  desc 'Active Directory (AD) is dependent on several Windows services.  If one or more of these services is not configured for automatic startup, AD functions may be partially or completely unavailable until the services are manually started.  This could result in a failure to replicate data or to support client authentication and authorization requests.'
  desc 'check', 'Run "services.msc" to display the Services console.

Verify the Startup Type for the following Windows services: 
- Active Directory Domain Services
- DFS Replication
- DNS Client
- DNS server
- Group Policy Client
- Intersite Messaging
- Kerberos Key Distribution Center
- NetLogon 
- Windows Time (not required if another time synchronization tool is implemented to start automatically)

If the Startup Type for any of these services is not Automatic, this is a finding.'
  desc 'fix', 'Ensure the following services that are critical for directory server operation are configured for automatic startup.

- Active Directory Domain Services
- DFS Replication
- DNS Client
- DNS server
- Group Policy Client
- Intersite Messaging
- Kerberos Key Distribution Center
- NetLogon 
- Windows Time (not required if another time synchronization tool is implemented to start automatically)'
  impact 0.5
  ref 'DPMS Target Windows Server 2012-2012 R2 Domain Controller'
  tag check_id: 'C-27781r475560_chk'
  tag severity: 'medium'
  tag gid: 'V-226079'
  tag rid: 'SV-226079r794798_rule'
  tag stig_id: 'WN12-AD-000010-DC'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-27769r794797_fix'
  tag 'documentable'
  tag legacy: ['SV-51184', 'V-8327']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
