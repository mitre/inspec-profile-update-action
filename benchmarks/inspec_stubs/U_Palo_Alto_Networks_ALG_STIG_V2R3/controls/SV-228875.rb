control 'SV-228875' do
  title 'The Palo Alto Networks security platform must block traceroutes and ICMP probes originating from untrusted networks (e.g., ISP and other non-DoD networks).'
  desc "Only authorized personnel should be aware of errors and the details of the errors. Error messages are an indicator of an organization's operational state or can give configuration details about the network element.

The traceroute utility will display routes and trip times on an IP network.  An attacker can use traceroute responses to create a map of the subnets and hosts behind the boundary.  The traditional traceroute relies on TTL - time exceeded responses from network elements along the path and an ICMP port-unreachable message from the target host. In some Operating Systems such as UNIX, trace route will use UDP port 33400 and increment ports on each response.  Since blocking these UDP ports alone will not block trace route capabilities along with blocking potentially legitimate traffic on a network, it's unnecessary to block them explicitly.  Because traceroutes typically rely on ICMP Type 11 - Time exceeded message, the time exceeded message will be the target for implicitly or explicitly blocking outbound from the trusted network."
  desc 'check', 'Ask the Administrator which Security Policy blocks traceroutes and ICMP probes.

Go to Policies >> Security
View the identified Security Policy.

If the "Source Zone" field is not external and the "Source Address" field is not any, this is a finding.

If the "Destination Zone" fields do not include the internal and DMZ zones and the "Destination Address" field is not any, this is a finding.

Note: The exact number and name of zones is specific to the network.

If the "Application" fields do not include "icmp", "ipv6-icmp", and "traceroute", this is a finding.

If the "Actions" field does not show "Deny" as the resulting action, this is a finding.'
  desc 'fix', 'Although the default inter-zone Security Policy will deny this traffic, a specific Security Policy should be used.

To configure the security policy:
Go to Policies >> Security
Select "Add".
In the "Security Policy Rule" window, complete the required fields.
In the "General" tab, complete the "Name" and "Description" fields.
In the "Source" tab, complete the "Source Zone" and "Source Address" fields.
For the "Source Zone" field, select "external". 
For the "Source Address" field, select "any".
In the "Destination" tab, complete the "Destination Zone" and "Destination Address" fields. 
For the "Destination Zone" field, select the internal and DMZ zones.  Note: The exact number and name of zones are specific to the network.
For the "Destination Address" field, select "any".
In the "Applications" tab, select "icmp", "ipv6-icmp", "traceroute".
In the "Actions tab", select "Deny" as the resulting action.  Select the required Log Setting and Profile Settings as necessary.
Commit changes by selecting "Commit" in the upper-right corner of the screen.
Select "OK" when the confirmation dialog appears.'
  impact 0.5
  ref 'DPMS Target Palo Alto Networks ALG'
  tag check_id: 'C-31110r513920_chk'
  tag severity: 'medium'
  tag gid: 'V-228875'
  tag rid: 'SV-228875r557387_rule'
  tag stig_id: 'PANW-AG-000127'
  tag gtitle: 'SRG-NET-000402-ALG-000130'
  tag fix_id: 'F-31087r513921_fix'
  tag 'documentable'
  tag legacy: ['V-62631', 'SV-77121']
  tag cci: ['CCI-001314']
  tag nist: ['SI-11 b']
end
