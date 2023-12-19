control 'SV-228863' do
  title 'The Palo Alto Networks security platform must identify and log internal users associated with prohibited outgoing communications traffic.'
  desc "Without identifying the users who initiated the traffic, it would be difficult to identify those responsible for the prohibited communications. This requirement applies to those network elements that perform Data Leakage Prevention (DLP) (e.g., ALGs, proxies, or application-level firewalls).  

The Palo Alto Networks Security Platform uses User-ID to map a user's identity to an IP address.  This allows Administrators to configure and enforce firewall policies based on users and user groups in addition to network zones and addresses. If the user changes devices or the device is assigned a different IP address, User-ID tracks those changes and maintains the user to IP address mapping information.  This supports non-repudiation. 

Before a security policy can be written for groups of users, the relationships between the users and the groups they are members of must be established. This information can be retrieved from an LDAP directory, such as Active Directory or eDirectory."
  desc 'check', 'Log into device Command Line Interface.
Enter the command "show user ip-user-mapping all".
If the output is blank, this is a finding.

An alternate means to verify that User-ID is properly configured, view the URL Filtering and Traffic logs is to view the logs.
To view the URL Filtering logs:
Go to Monitor >> Logs >> URL Filtering

To view the  Traffic logs:
Go to Monitor >> Logs >> Traffic

User traffic originating from a trusted zone contains a username in the "Source User" column.
If the "Source User" column is blank, this is a finding.

Alternatively, verify that usernames are displayed in reports.
Go to Monitor >> Reports
Select the "Denied Applications Report".
If the "Source User" fields are empty, this is a finding.'
  desc 'fix', %q(User-ID can integrate with the enclave's systems using different methods; therefore, the exact configuration is dependent on the method chosen.  
Determine which method User-ID will use to integrate with the enclave's systems - Server Monitoring, Client Probing, Syslog User-ID Agent, Terminal Services Agent, or Captive Portal. 
Configure how groups and users are retrieved from the directory and which users groups are to be included in policies.
Configure the Security Policies that controls traffic from client hosts in the trust zone to the untrust zone.
Go to Policies >> Security
Select "Add" to create a new policy or select the Name of the Policy to edit it.
In the "Security Policy Rule" window, complete the required fields.
In the "General" tab, complete the "Name" and "Description" fields.
In the "Source" tab, complete the "Source Zone" and "Source Address" fields.  
In the "User" tab, select "any".
In the "Destination" tab, complete the "Destination Zone" and "Destination Address" fields. 
In the "Applications" tab, select the authorized applications.
In the "Service/URL Category" tab, select "application-default".
To add a service, select the "Service" check box, select "Add" and select a listed service or add a new service or service group.
In the "Actions" tab, select either "Deny" or "Allow (as required)" as the resulting action.
Select the required Log Setting and Profile Settings as necessary.
Commit changes by selecting "Commit" in the upper-right corner of the screen.
Select "OK" when the confirmation dialog appears.)
  impact 0.5
  ref 'DPMS Target Palo Alto Networks ALG'
  tag check_id: 'C-31098r513884_chk'
  tag severity: 'medium'
  tag gid: 'V-228863'
  tag rid: 'SV-228863r831605_rule'
  tag stig_id: 'PANW-AG-000109'
  tag gtitle: 'SRG-NET-000370-ALG-000125'
  tag fix_id: 'F-31075r513885_fix'
  tag 'documentable'
  tag legacy: ['SV-77097', 'V-62607']
  tag cci: ['CCI-002400']
  tag nist: ['SC-7 (9) (b)']
end
