control 'SV-214211' do
  title 'The DNS implementation must enforce a Discretionary Access Control (DAC) policy that limits propagation of access rights.'
  desc 'Discretionary Access Control (DAC) is based on the premise that individual users are "owners" of objects and therefore have discretion over who should be authorized to access the object and in which mode (e.g., read or write). Ownership is usually acquired as a consequence of creating the object or via specified ownership assignment. In a DNS implementation, DAC should be granted to a minimal number of individuals and objects because DNS does not interact directly with users and users do not store and share data with the DNS application directly.

The primary objective of DNS authentication and access control is the integrity of DNS records; only authorized personnel must be able to create and modify resource records, and name servers should only accept updates from authoritative master servers for the relevant zones. Integrity is best assured through authentication and access control features within the name server software and the file system the name server resides on. In order to protect the zone files and configuration data, which should only be accessed by the name service or an administrator, access controls need to be implemented on files, and rights should not be easily propagated to other users. Lack of a stringent access control policy places the DNS infrastructure at risk to malicious persons and attackers, in addition to potential denial of service to network resources.

DAC allows the owner to determine who will have access to objects they control. An example of DAC includes user-controlled file permissions. DAC models have the potential for the access controls to propagate without limit, resulting in unauthorized access to said objects.

When applications provide a DAC mechanism, the DNS implementation must be able to limit the propagation of those access rights.'
  desc 'check', 'Infoblox utilizes a robust permission structure that provides for granular configuration of user access to the administrative interface.

Review the Infoblox Overview document for more information on access control and inheritance.

If an access policy limiting propagation of access rights is not configured, this is a finding.'
  desc 'fix', 'Navigate to Administration >> Administrators, and reconfigure "Admins", "Groups", "Roles", "Permissions", and "Authentication Policy" to the desired permissions.'
  impact 0.5
  ref 'DPMS Target Infoblox 7.x DNS'
  tag check_id: 'C-15426r295896_chk'
  tag severity: 'medium'
  tag gid: 'V-214211'
  tag rid: 'SV-214211r612370_rule'
  tag stig_id: 'IDNS-7X-000830'
  tag gtitle: 'SRG-APP-000516-DNS-000099'
  tag fix_id: 'F-15424r295897_fix'
  tag 'documentable'
  tag legacy: ['SV-83107', 'V-68617']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
