control 'SV-8797' do
  title 'The LAN supporting VVoIP services for command and control (C2) users must provide assured services in accordance with the Unified Capabilities Requirements (UCR).'
  desc 'Voice services in support of high priority military command and control precedence must meet minimum requirements for reliability and survivability of the supporting infrastructure. Design requirements for networks supporting DoD VVoIP implementations are in the UCR, specifying assured services supporting DoD IP based voice services. The UCR defines LAN design requirements for redundancy of equipment and interconnections, minimum requirements for bandwidth, specifications for backup power, and the maximum number of endpoints tolerable by a single point of failure. Policy sets the minimum requirements for the availability and reliability of VVoIP systems Special-C2 users is 99.999%, C2 users is 99.997%, C2Routine only users (C2R) and non-C2 users is 99.9%.'
  desc 'check', 'If the system does not support a minimum of 96 instruments, this requirement is not applicable.

Review site documentation to confirm the LAN supporting VVoIP services for C2 users provides assured services in accordance with the UCR. Specific attention should be given in the areas of: 
- Bandwidth and traffic engineering (25% voice, 25% video, 50% data) 
- No single point of failure affecting service to greater than 96 instruments.
- Equipment reliability
- Equipment redundancy above the access layer
- Equipment robustness and bandwidth capability
- Connection redundancy above the access layer
- Connection bandwidth capability
- Access layer switch size (number of phones served)
- Backup power for all equipment:
 + 2 hours for all equipment and instruments supporting C2 users
 + 8 hours for all equipment and instruments supporting Special-C2 users

If the LAN supporting VVoIP services for C2 users does not provide assured services in accordance with the UCR, this is a finding.'
  desc 'fix', 'Implement and document that the LAN supporting VVoIP services for C2 users provides assured services in accordance with the UCR.'
  impact 0.3
  ref 'DPMS Target IP Voice/Video/UC Site / System'
  tag check_id: 'C-23781r3_chk'
  tag severity: 'low'
  tag gid: 'V-8302'
  tag rid: 'SV-8797r3_rule'
  tag stig_id: 'VVoIP 5105'
  tag gtitle: 'VVoIP 5105'
  tag fix_id: 'F-20217r3_fix'
  tag 'documentable'
  tag responsibility: 'Information Assurance Officer'
end
