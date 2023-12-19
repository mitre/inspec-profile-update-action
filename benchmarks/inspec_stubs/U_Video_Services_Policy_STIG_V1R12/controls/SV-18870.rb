control 'SV-18870' do
  title 'VTU/CODEC is not properly configured to support streaming.'
  desc 'In the event conference streaming directly from a VTU/CODEC is approved for a given conference, the administrator will need to properly configure the VTU to support the streamed conference. One of these measures is to set a one-time-use password for the streamed media. Another measure is to install configuration settings to limit the reach of the streamed media across the network to only those portions that are to receive it. This is done by setting the TTL as low as possible. A mitigation that can be used for the lack of access control for IP multicast is to use different multicast addresses and IP ports each time a streaming session is configured. First these should never be the default address(es) or ports used by the vendor’s system and they should be randomly selected.  

Note:  Streaming is a feature of the VTU that could be turned on and configured for monitoring purposes by an adversary if the administrative access to the VTU is compromised. This is another reason why it is imperative to change all access codes and passwords on the VTU as required earlier. Additionally, users must be trained to recognize any displayed indication provided by the VTU that it is in streaming mode.

Note: For additional information regarding the vulnerabilities associated with VTC streaming, see the discussion under RTS-VTC 2340'
  desc 'check', '[IP];  Interview the IAO to validate compliance with the following requirement:

If and when implementing streaming, ensure the following streaming configuration settings are implemented as prudent to minimize accessibility to the media stream:
- Implement and distribute a temporary password for the session. For best protection of the system, this password is used one time and not repeated. This password must not match any other user or administrative password.
- Enter an appropriate address and IP port for delivery of the media stream. If multicast is used, these are different from the default settings used by the vendor, and are randomly different each time they are used. 
- Set TTL/router hops to an appropriate number to limit the range of distribution of the media stream to within the local LAN or Intranet as required. This number should be limited to 1 for the local network, 15 or 16 for the campus, 25 for the adjoining site. Never enter a high number such as 64 and above since this will extend the reach to a region or the world as the number goes higher.

Determine/review site policy/procedure for the implementation of approved VTC CODEC streaming. Review configuration settings to be used. If any CODECs are currently approved for and configured to stream, inspect or have the SA demonstrate the configuration used. This is a finding if the policy/procedure and/or configuration does not match or support the requirement items listed above.'
  desc 'fix', '[IP]; Perform the following tasks if streaming of a VTC CODEC session is approved and is to be implemented:
- Implement and distribute a temporary password for the session. This password is used one time and never repeated. This password must not match any other user or administrative password.
- Configure the CODEC by entering an appropriate address and IP port for delivery of the media stream. If multicast is used, these must be different from the default settings used by the vendor, and are randomly different each time they are used. 
- Configure the CODEC by setting TTL/router hops to an appropriate number to limit the range of distribution of the media stream to within the local LAN or Intranet as required. This number should be limited to 1 for the local network, 15 or 16 for the campus, 25 for the adjoining site. Never enter a high number such as 64 and above since this will extend the reach to a region or the world as the number goes higher.'
  impact 0.5
  ref 'DPMS Target VTC Endpoint Site/System/Enclave'
  tag check_id: 'C-18966r1_chk'
  tag severity: 'medium'
  tag gid: 'V-17696'
  tag rid: 'SV-18870r1_rule'
  tag stig_id: 'RTS-VTC 2420.00'
  tag gtitle: 'RTS-VTC 2420.00 [IP]'
  tag fix_id: 'F-17593r1_fix'
  tag 'documentable'
  tag severity_override_guidance: 'NONE'
  tag potential_impacts: 'The inadvertent or improper disclosure of sensitive or classified information to a caller of a VTU that may not have an appropriate need-to-know or proper security clearance.'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
end
