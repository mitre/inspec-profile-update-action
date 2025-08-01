control 'SV-21739' do
  title 'The network IDS is not configured or implemented such that it can monitor the traffic to/from the required VVoIP firewall/EBC (function) as well as the traffic to/from the data firewall (function).'
  desc 'The purpose of the Internal Network IDS is to provide a backup for the enclave firewall(s) in the event they are compromised or mis-configured such that traffic which is normally blocked ends up being passed as well as to detect other malicious activity entering (or leaving) the enclave. As such the NIDS must be implemented in such a manner that it monitors all traffic flowing through the data and VVoIP firewalls. Minimally, it will detect improper data protocol traffic coming through the VVoIP firewall. While the NIDS will not be able to inspect the VVoIP signaling and bearer packet payload due to its encryption, it could detect anomalous behavior in the flow of these packets.

Additionally, per the NI STIG, the NIDS is required to be a separate device from the firewall for reliability reasons. If the common firewall/IDS platform is compromised, both the firewall and IDS is vulnerable.'
  desc 'check', 'Interview the IAO to confirm compliance with the following requirement: 

In the event the VVoIP system within the enclave is interconnected with other VVoIP systems across the WAN, ensure the required internal Network IDS (NIDS) is implemented such that it monitors the traffic to/from both the data firewall (function) and the required VVoIP firewall/EBC (function). 
NOTE: This is applicable whether the VVoIP system is integrated with the DISN IPVS or not.

This is a finding in the event the NIDS is not implemented such that it sees traffic from the VVoIP firewall (EBC or other) as well as the data firewall.

NOTE: The NIDS monitoring the VVoIP firewall may be the same device that monitors the data firewall or it may be a separate device. In the event it is a separate device, it is subject to all Network Infrastructure STIG requirements to include CNDSP monitoring if applicable.

NOTE: The Network Infrastructure STIG recognizes that many of today’s NIDS are also intrusion prevention devices. The NI STIG refers to the required NIDS as an Intrusion detection/Prevention System (IDPS).'
  desc 'fix', 'In the event the VVoIP system within the enclave is interconnected with other VVoIP systems across the WAN, ensure the required internal Network IDS (NIDS) is implemented such that it monitors the traffic to/from both the data firewall (function) and the required VVoIP firewall/EBC (function).

NOTE: This is applicable whether the VVoIP system is integrated with the DISN IPVS or not.'
  impact 0.5
  ref 'DPMS Target IP Voice/Video/UC Site / System'
  tag check_id: 'C-23872r1_chk'
  tag severity: 'medium'
  tag gid: 'V-19598'
  tag rid: 'SV-21739r1_rule'
  tag stig_id: 'VVoIP 6125 (DISN-IPVS)'
  tag gtitle: 'Deficient design: NIDS protection for VVoIP'
  tag fix_id: 'F-20297r1_fix'
  tag 'documentable'
  tag severity_override_guidance: 'None'
  tag potential_impacts: 'Unauthorized and undetected access or compromise of the enclave or the services it supports'
  tag responsibility: 'Information Assurance Officer'
  tag ia_controls: 'DCBP-1, ECSC-1'
end
