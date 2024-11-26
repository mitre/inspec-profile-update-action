control 'SV-55757' do
  title 'An IDS/IPS must protect the IP-based VTC system within the enclave.'
  desc 'An enclave supporting an IP-based VTC system that must communicate across an IP WAN must be protected by the existing network IDS/IPS or by the implementation of an IDS/IPS that is dedicated to the VTC enclave. The IDS/IPS must comply with the requirements of the IDS/IPS Security Technical Implementation Guide. Please refer to the “IDPS Security Guidance at a Glance” for additional implementation guidance for Network Intrusion Detection/Prevention Systems.'
  desc 'check', 'Review network documentation and verify that the existing enclave network IDS/IPS is protecting the VTC system or that a dedicated IDS/IPS is protecting the VTC enclave. If there is no IDS/IPS protecting the VTC system, this is a finding.'
  desc 'fix', 'Obtain and configure a dedicated IDS/IPS or configure the existing enclave IDS/IPS to protect the VTC system.'
  impact 0.5
  ref 'DPMS Target VTC Endpoint Site/System/Enclave'
  tag check_id: 'C-49185r3_chk'
  tag severity: 'medium'
  tag gid: 'V-43028'
  tag rid: 'SV-55757r1_rule'
  tag stig_id: 'RTS-VTC 6020'
  tag gtitle: 'RTS-VTC 6020 [IP]'
  tag fix_id: 'F-48612r2_fix'
  tag 'documentable'
  tag responsibility: 'Information Assurance Officer'
  tag ia_controls: 'EBBD-2'
end
