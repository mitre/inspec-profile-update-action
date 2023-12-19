control 'SV-242174' do
  title 'The Trend Micro TPS must restrict or block harmful or suspicious communications traffic between interconnected networks based on attribute- and content-based inspection of the source, destination, headers, and/or content of the communications traffic.'
  desc 'The TPS enforces approved authorizations by controlling the flow of information between interconnected networks to prevent harmful or suspicious traffic does spread to these interconnected networks.

Information flow control policies and restrictions govern where information is allowed to travel as opposed to who is allowed to access the information. The TPS includes policy filters, rules, signatures, and behavior analysis algorithms that inspects and restricts traffic based on the characteristics of the information and/or the information path as it crosses external/perimeter boundaries. TPS components are installed and configured such that they restrict or block detected harmful or suspect information flows based on attribute- and content-based inspection of the source, destination, headers, and/or content of the communications traffic.'
  desc 'check', %q(1. In the Trend Micro SMS, navigate to "Profiles" and select the organization's profile. 
2. If there is not one configured, select "Default". 
3. Then select "Traffic Management". 
4. Ensure there are traffic management filters for each zone based on unapproved traffic directions. For example, if traffic from the management network is not allowed to access the external network, look for this rule. 

If a rule is not in place to enforce this, this is a finding.)
  desc 'fix', %q(1. In the Trend Micro SMS, navigate to "Profiles" and select the organization's profile. 
2. If there is not one configured, select "Default". 
3. Then select "Traffic Management". 
4. Select "New" then type a name. For example, "Management network blocked to internet". 
5. Ensure block is selected. 
6. Add necessary comment. 
7. Ensure the direction A to B, or B to A is identified. 
8. Enter the following for detailed addressing: 
   a. Select IP for IPv4 or IPv6 for IPv6. 
   b. Under Source Address type the subnet for the management network. 
   c. Under destination address, select any. 

This is an example of blocking management traffic from accessing internet communications. Add additional traffic management rules to block or allow traffic based on IPv4 or IPv6 protocol, ICMP/ICMPv6 types, and/or source and destination addresses and TCP/UDP ports.)
  impact 0.7
  ref 'DPMS Target Trend Micro TippingPoint IDPS'
  tag check_id: 'C-45449r710063_chk'
  tag severity: 'high'
  tag gid: 'V-242174'
  tag rid: 'SV-242174r754436_rule'
  tag stig_id: 'TIPP-IP-000080'
  tag gtitle: 'SRG-NET-000019-IDPS-00019'
  tag fix_id: 'F-45407r710064_fix'
  tag 'documentable'
  tag cci: ['CCI-001414']
  tag nist: ['AC-4']
end
