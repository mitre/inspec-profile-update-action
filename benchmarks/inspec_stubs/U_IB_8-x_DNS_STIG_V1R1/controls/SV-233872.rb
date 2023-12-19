control 'SV-233872' do
  title 'The Infoblox system must use a security policy that limits the propagation of access rights.'
  desc 'Discretionary Access Control (DAC) is based on the premise that individual users are "owners" of objects and therefore have discretion over who should be authorized to access the object and in which mode (e.g., read or write). Ownership is usually acquired as a consequence of creating the object or via specified ownership assignment. In a DNS implementation, DAC should be granted to a minimal number of individuals and objects because DNS does not interact directly with users and users do not store and share data with the DNS application directly.

The primary objective of DNS authentication and access control is the integrity of DNS records; only authorized personnel must be able to create and modify resource records, and name servers should only accept updates from authoritative master servers for the relevant zones. Integrity is best assured through authentication and access control features within the name server software and the file system the name server resides on. 

To protect the zone files and configuration data, which should only be accessed by the name service or an administrator, access controls need to be implemented on files, and rights should not be easily propagated to other users. Lack of a stringent access control policy places the DNS infrastructure at risk to malicious persons and attackers, in addition to potential denial of service to network resources.

DAC allows the owner to determine who will have access to objects they control. An example of DAC includes user-controlled file permissions. DAC models have the potential for the access controls to propagate without limit, resulting in unauthorized access to objects.

When applications provide a DAC mechanism, the DNS implementation must be able to limit the propagation of those access rights.'
  desc 'check', 'Infoblox NIOS uses a robust permission structure that provides for granular configuration of user access to the administrative interface. Review the Infoblox Overview document for more information on access control and inheritance, and the Administrator Guide for comprehensive information.  

1. Navigate to Administration >> Administrators. Review the "Authentication Policy" tab, which will display the authentication methods and order.  
2. Review the "Admins", "Groups", "Roles", and "Permissions" tabs to display the specific accounts, roles, and permissions.
3. Verify the local assignment policy against the configured accounts.

If an access policy limiting propagation of access rights is not configured, or the Infoblox system is not configured in accordance with local access policy, this is a finding.'
  desc 'fix', '1. Review the Infoblox Administrator Guide for comprehensive instructions if necessary. 
2. Navigate to Administration >> Administrators tab. 
3. Edit the "Admins", "Groups", "Roles", "Permissions", and "Authentication Policy" tabs and set to the desired permissions.'
  impact 0.5
  ref 'DPMS Target Infoblox 8.x DNS'
  tag check_id: 'C-37057r611136_chk'
  tag severity: 'medium'
  tag gid: 'V-233872'
  tag rid: 'SV-233872r621666_rule'
  tag stig_id: 'IDNS-8X-400014'
  tag gtitle: 'SRG-APP-000516-DNS-000099'
  tag fix_id: 'F-37022r611137_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
