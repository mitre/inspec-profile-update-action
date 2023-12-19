control 'SV-17104' do
  title 'PC communications application server association is not properly limited.'
  desc 'All voice, video, UC, or collaboration communications endpoints must be configured to only associate with approved DoD controllers, gateways, and/or servers. While this is the norm for hardware based endpoints in a LAN, it is even more important for PC application based endpoints. Such endpoints must not accept service from just any available system. Such a system could actually be in a different organization than the one the application belongs to, depending upon how the application seeks out its controller/server. Peer-to-peer, or direct PC application-to-application communications are based on knowing the other endpoint’s IP address is not permitted. All communications applications must contact their designated session controller(s), gateway(s), or server(s) for authorization to operate. 

NOTE: This is the general rule for all communications types with the exception of point-to-point VTC sessions between hardware based VTC CODECs.

An additional consideration is the reliability of a critical voice communications service and its continuity of operations. This is a prime concern for hardware based VoIP systems which are intended or are designed to provide assured service. Such critical systems must be supported by redundant controllers.  If a soft-phone associated with such a system is to be reliable, it must be configured to interact with its primary controller(s) and at least one backup.'
  desc 'check', 'Interview the IAO to validate compliance with the following requirement:

Ensure PC based voice, video, UC, or collaboration communications applications are configured such that they only contact and associate with their designated and approved DoD controllers, gateways, and/or servers and their approved backups.

Determine what the application’s permitted controllers, gateways, and/or servers including backups should be from the IAO. Review application configuration settings on a random sampling of PCs to determine if only the permitted controllers, gateways, and/or servers are configured. Further determine if users (not SAs) can reconfigure these settings. This is a finding if PC based voice, video, UC, or collaboration communications applications are NOT configured such that they only contact and associate with their designated and approved DoD controllers, gateways, and/or servers and their approved backups or if general users (not SAs) can reconfigure the related settings.'
  desc 'fix', 'Ensure PC based voice, video, UC, or collaboration communications applications are configured such that they only contact and associate with their designated and approved DoD controllers, gateways, and/or servers and their approved backups.

Configure PC based voice, video, UC, or collaboration communications applications such that they only contact and associate with their designated and approved DoD controllers, gateways, and/or servers and their approved backups. Further ensure general application users cannot reconfigure these settings.'
  impact 0.5
  ref 'DPMS Target IP Voice/Video/UC Site / System'
  tag check_id: 'C-17160r1_chk'
  tag severity: 'medium'
  tag gid: 'V-16116'
  tag rid: 'SV-17104r1_rule'
  tag stig_id: 'VVoIP 1805 (REMOTE)'
  tag gtitle: 'Deficient Config: PC Comm App. Server Association'
  tag fix_id: 'F-16222r1_fix'
  tag 'documentable'
  tag severity_override_guidance: 'NONE'
  tag potential_impacts: 'Compromise of the supported communications or supporting PC.'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
end
