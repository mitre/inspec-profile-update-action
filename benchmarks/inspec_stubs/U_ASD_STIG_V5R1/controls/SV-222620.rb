control 'SV-222620' do
  title 'Application web servers must be on a separate network segment from the application and database servers if it is a tiered application operating in the DoD DMZ.'
  desc 'A tiered application usually consists of 3 tiers, the web layer (presentation tier), the application layer (application logic tier), and the database layer (data storage tier).

Using one system for hosting all 3 tiers introduces risk that if one tier is compromised, there are no additional protection layers available to defend the other tiers.
Security controls must be in place in order to provide different levels and types of defenses for each type of server based upon data protection requirements identified by policy or data owner.

DoD DMZ policy specifies that logical separation is allowed but when hosting different data types on the same server, physical separation is required.

1) Unrestricted web servers and Restricted web servers must be on separate virtual or physical servers from Private web servers, application servers, or database servers.
2) Unrestricted web servers and Restricted web servers can either be on separate physical servers from each other, or they can be on separate virtual servers.
3) If application and database servers have been separated by service type into Unrestricted, Restricted, and Private servers (permitted but not required in Increment 1 Phase 1), they must be on separate virtual or physical servers from each other by server type (Application or Database) and by service type (Unrestricted, Restricted, or Private).

Reference the DoD DMZ STIG for details on data types and separation requirements.

Security controls include firewalls or other forms of access controls that restrict the ability to traverse the network from one system to the other.

Separation can be performed either physically or logically based upon data protection and application protection design requirements.

Physically separate networks require distinct physical network devices for connections (e.g., two separate switches or two separate routers).

Physically separate machines utilize a non-virtual OS.

Logically separate networks are usually implemented via a VLAN.

Logically separate systems are implemented with virtual machines or other system emulation.

Security controls are firewall rules or ACLs that provide access restrictions on network traffic and limit communications between systems to only application and application/system support traffic.

For complete explanation of DoD DMZ requirements, reference DoD DMZ requirements.'
  desc 'check', 'Review the application documentation.

Review the application data protection requirements and identify if all data types hosted on server are identical.

Review the network diagram and identify web servers/web services, web application servers, and database servers.

If the application is not hosted in the DoD DMZ, this requirement is not applicable.

Verify the application web servers are separated from the application and database servers if the application is a tiered design as per DoD DMZ STIG requirements.

If the application is tiered and the network infrastructure hosting the application is not configured to provide separation and security access controls between the tiered layers in accordance with DoD DMZ requirements, this is a finding.'
  desc 'fix', 'Separate web server from other application tiers and place it on a separate network segment apart from the application and database servers in accordance with DoD DMZ data access controls requirements.'
  impact 0.7
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-24290r493768_chk'
  tag severity: 'high'
  tag gid: 'V-222620'
  tag rid: 'SV-222620r508029_rule'
  tag stig_id: 'APSC-DV-002890'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-24279r493769_fix'
  tag 'documentable'
  tag legacy: ['V-70293', 'SV-84915']
  tag cci: ['CCI-000366', 'CCI-002225']
  tag nist: ['CM-6 b', 'AC-6 (4)']
end
