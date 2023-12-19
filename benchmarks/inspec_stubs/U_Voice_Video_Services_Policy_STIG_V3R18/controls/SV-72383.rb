control 'SV-72383' do
  title 'Sufficient backup power must be provided for LAN Infrastructure, WAN boundary, VVoIP infrastructure, and VVoIP endpoints to support non-C2 user accessible endpoints for emergency life-safety and security calls.'
  desc 'Unified Capabilities (UC) users require different levels of capability depending upon command and control needs. Special-C2 decision makers requiring Flash or Flash Override precedence must have eight hours of continuous backup power at all times. C2 users requiring Immediate or Priority precedence must have two hours of continuous backup power.

Interrupting any of the routing or switching infrastructures will disrupt VVoIP service. If the infrastructure is interrupted, command and control communications are disrupted, preventing critical communications from occurring. When implementing a VVoIP system without considering UPS system power needs for the VVoIP controllers and endpoints as well as the entire LAN, and supporting those needs with UPSs, communications availability is reduced. As such, all elements of the LAN infrastructure, WAN boundary, VVoIP infrastructure, and VVoIP endpoints directly supporting users with precedence needs must be provided with sufficient backup power to meet availability requirements. This reduction in availability threatens facility and personal security and safety as well as life safety during a power failure.'
  desc 'check', 'Inspect the VVoIP system design for evidence of continuous backup power to the infrastructure and command and control (C2) users.

Ensure a UPS system is provided for all parts of the VVoIP infrastructure, including the core LSC/MFSS, adjunct systems providing critical services, SBC, CER, LAN elements, and endpoints as follows: 
- All VVoIP system devices including portions of the LAN that supports non-C2 users are provided 15 minutes of UPS in support of emergency life-safety and security communications during a power failure.
- In no case should a UPS system immediately, or within a short time, drop power to the supported equipment when primary power is removed. This would indicate an undersized or defective UPS unit.

Determine if the infrastructure assets being reviewed support non-C2 users. If non-C2 users are supported and a 15 minutes of backup power is not provided for LAN Infrastructure, WAN boundary, VVoIP infrastructure, and VVoIP endpoints for emergency life-safety and security calls, this is a finding.

NOTE: The requirement for UPS support to non-C2 user communications is negated when such users have an alternate reliable means of communicating in such situations. A suitable alternative would be a policy and SOP in effect requiring users to evacuate the facility to a location where mobile communications capability is available and acceptable.'
  desc 'fix', 'Ensure a UPS system is provided for all parts of the VVoIP infrastructure, including the core LSC/MFSS, adjunct systems providing critical services, SBC, CER, LAN elements, and endpoints. All VVoIP system devices including portions of the LAN supporting non-C2 users are provided a minimum 15 minutes of UPS in support of emergency life-safety and security communications during a power failure.

Note: The 15 minutes of UPS mandated by this requirement is a minimum. Backup times of 30-60 minutes are preferred. UPS systems supplying power to infrastructure supporting non-C2 users should also support environmental power to prevent equipment failures.'
  impact 0.3
  ref 'DPMS Target IP Voice/Video/UC Site / System'
  tag check_id: 'C-58729r2_chk'
  tag severity: 'low'
  tag gid: 'V-57953'
  tag rid: 'SV-72383r2_rule'
  tag stig_id: 'VVoIP 1223 (Non-C2)'
  tag gtitle: 'VVoIP 1223'
  tag fix_id: 'F-63161r2_fix'
  tag 'documentable'
  tag responsibility: 'Information Assurance Officer'
end
