control 'SV-69601' do
  title 'The IDPS must block malicious ICMP packets by properly configuring ICMP signatures and rules.'
  desc 'Internet Control Message Protocol (ICMP) messages are used to provide feedback about problems in the network. These messages are sent back to the sender to support diagnostics. However, some messages can also provide host information, network topology, and a covert channel that may be exploited by an attacker.

Given the prevalence of ICMP traffic on the network, monitoring for malicious ICMP traffic would be cumbersome. Vendors provide signatures and rules which filter for known ICMP traffic exploits.'
  desc 'check', 'Verify the IDPS blocks malicious ICMP packets by properly configuring ICMP signatures and rules.

If the IDPS does not block malicious ICMP packets by properly configuring ICMP signatures and rules, this is a finding.'
  desc 'fix', 'Configure the IDPS to block malicious ICMP packets by properly configuring ICMP signatures and rules.'
  impact 0.5
  ref 'DPMS Target SRG-NET-IDPS'
  tag check_id: 'C-55979r1_chk'
  tag severity: 'medium'
  tag gid: 'V-55355'
  tag rid: 'SV-69601r1_rule'
  tag stig_id: 'SRG-NET-000273-IDPS-00204'
  tag gtitle: 'SRG-NET-000273-IDPS-00204'
  tag fix_id: 'F-60223r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001312']
  tag nist: ['SI-11 a']
end
