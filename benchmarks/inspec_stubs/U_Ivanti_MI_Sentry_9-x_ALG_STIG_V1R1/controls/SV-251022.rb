control 'SV-251022' do
  title 'The Sentry must be configured to prohibit or restrict the use of functions, ports, protocols, and/or services, as defined in the PPSM CAL and vulnerability assessments.'
  desc 'In order to prevent unauthorized connection of devices, unauthorized transfer of information, or unauthorized tunneling (i.e., embedding of data types within data types); organizations must disable or restrict unused or unnecessary physical and logical ports/protocols on information systems.

ALGs are capable of providing a wide variety of functions and services. Some of the functions and services provided by default may not be necessary to support essential organizational operations. DoD continually assesses the ports, protocols, and services that can be used for network communications. Some ports, protocols or services have known exploits or security weaknesses. Network traffic using these ports, protocols, and services must be prohibited or restricted in accordance with DoD policy. The ALG is a key network element for preventing these non-compliant ports, protocols, and services from causing harm to DoD information systems.

The network ALG must be configured to prevent or restrict the use of prohibited ports, protocols, and services throughout the network by filtering the network traffic and disallowing or redirecting traffic as necessary. Default and updated policy filters from the vendors will disallow older version of protocols and applications and will address most known non-secure ports, protocols, and/or services. However, sources for further policy filters are the IAVMs and the PPSM requirements.

'
  desc 'check', 'View the configuration and vendor documentation of the Sentry application to find the minimum ports, protocols, and services required for Sentry operation.

1. Log in to MobileIron Sentry System Manager.
2. Go to Security >> Access Control Lists >> ACLs.
3. Check all the ACLs to determine if the service restricted has an ACL already available.

If it does not, this is a finding.'
  desc 'fix', 'Disable ports, protocols, and/or services not required for Sentry operation.

1. Log in to the Standalone Sentry System Manager.
2. Go to Security >> Access Control Lists >> ACLs.
3. Check all the ACLs to determine if the service restricted has an ACL already available. If it does not, click "Add".
4. In the "Name" field, enter a name to identify the ACL.
5. In the "Description" field, enter text to clarify the purpose of the ACL.
6. Click "Save".
7. Select the new ACL created and click it, which should open a "Modify ACL" dialog box.
8. Click "Add" to add an access control entry (ACE) to the ACL. Each ACE consists of a combination of the network hosts and services configured for use in ACLs.
9. Use the following guidelines to complete the form:
Source Network 
Destination Network
Service
Action - Select Permit or Deny from the drop-down list.
Connections Per Minute
10. Click "Apply".'
  impact 0.5
  ref 'DPMS Target Ivanti MobileIron Sentry 9.x ALG'
  tag check_id: 'C-54457r802286_chk'
  tag severity: 'medium'
  tag gid: 'V-251022'
  tag rid: 'SV-251022r802288_rule'
  tag stig_id: 'MOIS-AL-000360'
  tag gtitle: 'SRG-NET-000132-ALG-000087'
  tag fix_id: 'F-54411r802287_fix'
  tag satisfies: ['SRG-NET-000132-ALG-000087', 'SRG-NET-000512-ALG-000062']
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-000382']
  tag nist: ['CM-6 b', 'CM-7 b']
end
