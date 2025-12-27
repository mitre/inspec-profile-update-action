control 'SV-72381' do
  title 'Two hours of backup power must be provided for LAN Infrastructure, WAN boundary, VVoIP infrastructure, and VVoIP endpoints to support Immediate or Priority precedence C2 users.'
  desc 'Unified Capabilities (UC) users require different levels of capability depending upon command and control needs. Special-C2 decision makers requiring Flash or Flash Override precedence must have eight hours of continuous backup power at all times. C2 users requiring Immediate or Priority precedence must have two hours of continuous backup power.

Interrupting any of the routing or switching infrastructures will disrupt VVoIP service. If the infrastructure is interrupted, command and control communications are disrupted, preventing critical communications from occurring. When implementing a VVoIP system without considering UPS power needs for the VVoIP controllers and endpoints as well as the entire LAN, and supporting those needs with UPS systems, communications availability is reduced. As such, all elements of the LAN infrastructure, WAN boundary, VVoIP infrastructure, and VVoIP endpoints directly supporting users with precedence needs must be provided with sufficient backup power to meet availability requirements. This reduction in availability threatens facility and personal security and safety as well as life safety during a power failure.'
  desc 'check', 'Inspect the VVoIP system design for evidence of continuous backup power to the infrastructure and command and control (C2) users. Ensure a UPS system is provided for all parts of the VVoIP infrastructure, including the core LSC/MFSS, adjunct systems providing critical services, SBC, CER, LAN elements, and endpoints as follows:
- All VVoIP system devices including portions of the LAN that directly support one or more C2 users are minimally provided 2 hours UPS.
- All C2 user VVoIP endpoints relying on Power over Ethernet (PoE) must have power sourcing equipment (PSE) sized to support the asset and endpoints by the UPS for a minimum 2 hours.
- All C2 user VVoIP endpoints without PoE must be minimally provided 2 hours UPS.
- UPS systems (battery at a minimum; plus optional generator) supplying power to infrastructure that supports special-C2 and C2 users must also support environmental power (HVAC) such that equipment failures are prevented. 
- In no case should a UPS system immediately, or within a short time, drop power to the supported equipment when primary power is removed. This would indicate an undersized or defective UPS unit.

Determine if the infrastructure assets being reviewed directly support one or more C2 users. If no C2 users are supported, this requirement is not applicable. If C2 users are supported, determine if assets are provided with 2 hours of backup power. If 2 hours of backup power is not provided for LAN Infrastructure, WAN boundary, VVoIP infrastructure, and VVoIP endpoints to support C2 users, this is a finding.'
  desc 'fix', 'Ensure an UPS system is provided for all parts of the VVoIP infrastructure, including the core LSC/MFSS, adjunct systems providing critical services, SBC, CER, LAN elements, and endpoints. All VVoIP system devices including voice endpoints and portions of the LAN that directly support one or more C2 users must be minimally provided 2 hours UPS. Document the VVoIP system design with UPS implementation.

Note: UPS systems supplying power to infrastructure supporting special-C2 and C2 users must also support environmental power to prevent equipment failures. This support must be commensurate with the users supported (8 or 2 hours as appropriate).'
  impact 0.5
  ref 'DPMS Target IP Voice/Video/UC Site / System'
  tag check_id: 'C-58727r2_chk'
  tag severity: 'medium'
  tag gid: 'V-57951'
  tag rid: 'SV-72381r2_rule'
  tag stig_id: 'VVoIP 1222 (C2)'
  tag gtitle: 'VVoIP 1222'
  tag fix_id: 'F-63159r2_fix'
  tag 'documentable'
  tag responsibility: 'Information Assurance Officer'
end
