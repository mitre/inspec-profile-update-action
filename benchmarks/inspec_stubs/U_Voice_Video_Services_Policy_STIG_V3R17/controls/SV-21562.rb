control 'SV-21562' do
  title 'The LAN supporting VVoIP services must provide enhanced reliability, availability, and bandwidth.'
  desc 'The traditional circuit switched telecommunications network is highly available and reliable with 99.999% uptime for equipment and 99% to 99.9% for the entire system. This is achieved through a series of measures such as redundant hardware and network connectivity as well as backup power for the central switching equipment which also provides power for the subscriber instruments. The DoD circuit switched telecommunications network supports routine communications, emergency communications, and high priority military command and control precedence. As these services migrate from circuit-switched technologies to IP-based technologies, this reliability and support must migrate with the service. Similar measures enhance the reliability and availability of VVoIP services on an IP network.'
  desc 'check', 'If the system does not support a minimum of 96 instruments, this requirement is not applicable. Review site documentation, network diagrams, and design information to confirm the LAN supporting VVoIP services provides enhanced reliability, availability, and bandwidth. Specific attention should be given in the areas of: 
- Bandwidth and traffic engineering (25% voice, 25% video, 50% data) 
- No single point of failure affecting service to greater than 96 instruments.
- Equipment reliability
- Equipment redundancy above the access layer
- Equipment robustness and bandwidth capability
- Connection redundancy above the access layer
- Connection bandwidth capability
- Access layer switch size (number of phones served)
- Backup power for all equipment

If the LAN supporting VVoIP services does not provide enhanced reliability, availability, and bandwidth or is deficient in these areas, this is a finding.

This check is not intended to initiate an in depth analysis of the network design. If the LAN is not is not properly designed it should be easily discerned because many of the criteria will not be met unless the LAN was already designed for high reliability and availability before adding VVoIP services.'
  desc 'fix', 'Implement and document the LAN supporting VVoIP services. VVoIP services must provide enhanced reliability, availability, and bandwidth. Voice bandwidth engineering is based on 102 kbps (each direction) for each IP call for IPv4 and 110.0 kbps for IPv6. Video bandwidth engineering is not so simple since when present, a single video stream can utilize 160kbps to 7.5Mbps in addition to any audio stream.'
  impact 0.3
  ref 'DPMS Target IP Voice/Video/UC Site / System'
  tag check_id: 'C-23780r2_chk'
  tag severity: 'low'
  tag gid: 'V-19500'
  tag rid: 'SV-21562r2_rule'
  tag stig_id: 'VVoIP 5100'
  tag gtitle: 'VVoIP 5100'
  tag fix_id: 'F-20216r2_fix'
  tag 'documentable'
end
