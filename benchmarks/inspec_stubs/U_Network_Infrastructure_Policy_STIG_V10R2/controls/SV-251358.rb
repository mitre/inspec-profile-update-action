control 'SV-251358' do
  title 'External network connections must not bypass the enclaves perimeter security.'
  desc "Without taking the proper safeguards, external networks connected to the organization will impose security risks unless properly routed through the perimeter security devices. Since external networks to the organization are considered to be untrusted, this could prove detrimental since there is no way to verify traffic inbound or outbound on this backdoor connection. An attacker could carry out attacks or steal data from the organization without any notification. An external connection is considered to be any link from the organization's perimeter to the NIPRNet, SIPRNet, Commercial ISP, or other untrusted network outside the organization's defined security policy. The DREN and SREN are DoD's Research & Engineering Network. A DoD Network that is the official DoD long-haul network for computational scientific research, engineering, and testing in support of DoD's S&T and T&E communities. It has also been designated as a DoD IPv6 pilot network by the Assistant Secretary of Defense (Networks & Information Integration)/DoD Chief Information Officer ASD (NII)/DoD CIO. A DISN enclave should not have connectivity to the DREN unless approved by the AO and the requirements have been met for all external connections described in NET0130."
  desc 'check', "Review the network topology diagram and verify that ingress and egress traffic via external connections to the enclave do not bypass the enclave's perimeter security. 

If there are external connections to the enclave that bypass the enclaves' perimeter security, this is a finding."
  desc 'fix', "Disconnect any external network connections not routed through the organization's perimeter security or validated and approved by the AO."
  impact 0.5
  ref 'DPMS Target Network Infrastructure Policy'
  tag check_id: 'C-54793r806027_chk'
  tag severity: 'medium'
  tag gid: 'V-251358'
  tag rid: 'SV-251358r806029_rule'
  tag stig_id: 'NET0170'
  tag gtitle: 'NET0170'
  tag fix_id: 'F-54746r806028_fix'
  tag 'documentable'
  tag legacy: ['V-8052', 'SV-8538']
  tag cci: ['CCI-001102', 'CCI-001103']
  tag nist: ['SC-7 (4) (a)', 'SC-7 (4) (b)']
end
