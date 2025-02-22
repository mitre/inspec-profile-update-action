control 'SV-79731' do
  title 'The DataPower Gateway must have ICMP responses disabled on all interfaces facing untrusted networks.'
  desc 'Providing too much information in error messages risks compromising the data and security of the application and system. Organizations carefully consider the structure/content of error messages. The required information within error messages will vary based on the protocol and error condition. Information that could be exploited by adversaries includes, for example, ICMP messages that reveal the use of firewalls or access-control lists.

The DataPower appliance, by default, will respond to ICMP pings, Info requests, and Address Mask queries. This must be disabled on any interface facing an untrusted network or network with a lower security posture.'
  desc 'check', 'View each interface that is connected to a network that is less trusted or untrusted. In the DataPower web interface, navigate to Ethernet interface >> Network settings >> Internet Control Message Protocol (ICMP) Disable. 

If the Administrative State is not "Disable", this is a finding.'
  desc 'fix', 'In the DataPower web interface, navigate to Ethernet interface >> Network settings >> Internet Control Message Protocol (ICMP) Disable. Set the Administrative State to "Disable".'
  impact 0.5
  ref 'DPMS Target IBM DataPower XI52 ALG'
  tag check_id: 'C-65869r1_chk'
  tag severity: 'medium'
  tag gid: 'V-65241'
  tag rid: 'SV-79731r1_rule'
  tag stig_id: 'WSDP-AG-000061'
  tag gtitle: 'SRG-NET-000273-ALG-000129'
  tag fix_id: 'F-71181r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001312']
  tag nist: ['SI-11 a']
end
