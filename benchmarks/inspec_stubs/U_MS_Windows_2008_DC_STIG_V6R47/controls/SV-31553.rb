control 'SV-31553' do
  title 'Windows services that are critical for directory server operation must be configured for automatic startup.'
  desc 'Active Directory (AD) is dependent on several Windows services. If one or more of these services is not configured for automatic startup, AD functions may be partially or completely unavailable until the services are manually started. This could result in a failure to replicate data or to support client authentication and authorization requests.'
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
  ref 'DPMS Target Windows 2008'
  tag check_id: 'C-48695r2_chk'
  tag severity: 'medium'
  tag gid: 'V-8327'
  tag rid: 'SV-31553r2_rule'
  tag stig_id: 'DS00.3260_2008'
  tag gtitle: 'Prerequisite OS Services Startup'
  tag fix_id: 'F-47817r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
