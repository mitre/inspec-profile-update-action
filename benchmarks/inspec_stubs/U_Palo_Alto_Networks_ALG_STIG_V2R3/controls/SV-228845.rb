control 'SV-228845' do
  title 'The Palo Alto Networks security platform must deny network communications traffic by default and allow network communications traffic by exception (i.e., deny all, permit by exception).'
  desc "A deny-all, permit-by-exception network communications traffic policy ensures that only those connections that are essential and approved are allowed.  As a managed boundary interface between networks, the Palo Alto Networks security platform must block all inbound and outbound network traffic unless a policy filter is installed to explicitly allow it. The allow policy filters must comply with the site's security policy. A deny-all, permit–by-exception network communications traffic policy ensures that only those connections that are essential and approved are allowed.

By default, there are two security policies on the Palo Alto Networks firewall:
Allow traffic within the same zone (intra-zone)
Deny traffic from one zone to another zone (inter-zone).

No policy that circumvents the inter-zone policy is allowed. Traffic through the device is permitted by policies developed to allow only that specific traffic that the system or enclave requires."
  desc 'check', 'Go to Policies >> Security
Review each of the configured security policies in turn.
Select each policy in turn; in the "Security Policy Rule" window, if the "Source Address" has "Any" selected, the "Destination Address" has "Any" selected, the "Application" has "Any" selected, and the "Action" Setting is "Allow", this is a finding.

If any Security Policy is too broad (allowing all traffic either inbound or outbound), this is also a finding.'
  desc 'fix', 'Do not configure any policies or rules that violate a deny-all, permit-by-exception policy.
Configure policies that allow traffic through the device based only on the mission and system requirements.'
  impact 0.5
  ref 'DPMS Target Palo Alto Networks ALG'
  tag check_id: 'C-31080r513830_chk'
  tag severity: 'medium'
  tag gid: 'V-228845'
  tag rid: 'SV-228845r557387_rule'
  tag stig_id: 'PANW-AG-000051'
  tag gtitle: 'SRG-NET-000202-ALG-000124'
  tag fix_id: 'F-31057r513831_fix'
  tag 'documentable'
  tag legacy: ['V-62573', 'SV-77063']
  tag cci: ['CCI-001109']
  tag nist: ['SC-7 (5)']
end
