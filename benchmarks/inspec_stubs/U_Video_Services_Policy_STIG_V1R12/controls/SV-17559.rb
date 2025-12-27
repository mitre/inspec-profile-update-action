control 'SV-17559' do
  title 'Use of media streaming is not documented properly or is not configured securely.'
  desc 'Media Streaming as it is related to VTC systems permits a VTU to engage in a normal IP or ISDN connected conference with other VTUs while broadcasting (streaming) the conference audio and video to PC workstations over an IP based LAN to which it is connected. This permits a workstation user to view the conference in near real time but not to participate in it. VTUs may also stream other content such as pre-recorded media played from a VCR or similar media source and some VTUs support streaming while others do not. It seems that as vendors mature their streaming server technology and more products become available, they are removing the streaming capability from the CODEC where it presents greater vulnerability. 
     
Streaming from a VTU’s CODEC can also be used to record a conference by sending the stream to a recording/streaming server that can perform the recording function. These servers also serve as streaming distribution points. Recording/Streaming servers are discussed later. 
     
While streaming from a CODEC most often uses IP multicast, streams can also be sent to one receiver (e.g., PC or recording/distribution server), or to multiple receivers in the local broadcast domain 
     
IP multicast or broadcast streaming works best within a LAN where ample bandwidth is available and IP multicast is supported.  While multicast streaming is conceivable across a WAN such as the Internet, it is much less feasible and less reliable due to limited multicast support and access circuit bandwidth constraints. To use IP multicast, the network elements must be configured to support it.
     
To enable streaming, the following configuration items are needed:
     
- Destination address, unicast (address of specific destination, client or server), broadcast (local subnet or global), multicast (address configured on a router in the range 224.0.0.1-239.255.255.255)
- IP port(s) (some CODECs may require one port for audio and one for video)
- Time-To-Live (TTL) (i.e., number of router hops or routers to traverse) 
     
VTU Streaming can typically be activated by a user selecting it from a menu. It could also be possible to activate it by the simple press of a button on the remote control. As such, it could be possible to activate streaming by accident when it is not desired or required. Additionally, some VTUs permit a remote user to activate the feature. 
     
The “broadcast” or stream is received by a compatible client running on a PC. Examples of clients used are RealMedia Player™, Apple Quicktime™, VIC, or Cisco IP/TV. 
     
To receive a multicast stream, the recipient can do one of the following two things:
     
- First, they can use a web browser to access the IP address of the CODEC that is streaming. The user accesses the CODEC’s web page and clicks a link to receive the stream. This causes the browser to download an .sdp file (e.g., filename.sdp) that contains information about the stream and launch the streaming client. The .sdp file tells the client what IP address and port the stream can be found on as well as the compression types (protocols) being used. Accessing the streaming web page or .sdp file typically requires the use of a password before gaining access. Some vendors use the administrator password (not acceptable) while others use a “meeting password” In some cases the recipient (remote user) can also activate streaming (i.e., cause the CODEC to begin streaming) from this web page if it is not already activated. 
- The second method of access is essentially direct. The recipient uses the streaming client to retrieve the .sdp file from the CODECs IP address. Some streaming clients can access a multicast stream without the use of an .sdp file.
     
The only access control for streaming is that imposed by the CODEC for accessing its web page and/or retrieving the .sdp file. While this is effective using clients such as RealMedia Player™, Apple Quicktime™, which require the .sdp file information to function, there are other clients that do not. Using a client that does not, once the CODEC is streaming, anyone knowing the IP address and port for the stream can view the stream. There is no access control for viewing a media stream in this manner because IP provides no access control for joining an IP multicast group.
     
When streaming, there is no way of knowing who or how many recipients are viewing a conference. The number of possible recipients is virtually unlimited. Typically, there is only an indication on the VTU screen that the CODEC is streaming. Again, some VTUs permit streaming to be activated remotely by anybody who knows the IP address of the VTU and can access its streaming web page. As such, it could be possible for an unauthorized person to activate streaming and eavesdrop on the room or a conference in session. These vulnerabilities can greatly jeopardize the confidentiality of any given conference by broadcasting it on the connected LAN to indeterminate numbers of unknown recipients. 
     
An additional vulnerability that streaming presents to any conference, whether hosted on a central MCU, point-to-point, or a MCU integrated unto a VTU is that any meeting participant could accidentally or maliciously stream the meeting from their VTU if their VTU supports streaming. For these reasons, the activation and use of streaming from a VTU/CODEC is discouraged and must be tightly controlled by all IAOs who are responsible for any streaming capable VTU that might participate in a conference. CODECs must be configured in such a way that if streaming is activated, the stream can only be accessed by authorized individuals or be non-functional or inaccessible if activated by accident.
     
Generally speaking, the use of streaming to an IP multicast or broadcast address should never be used or activated unless it is required to fulfill a specific, validated, authorized, and documented mission requirement. This applies to both streaming from a CODEC or a recording/streaming server because of the inherent lack of full user/recipient access control. Streaming to a unicast address, i.e., one recipient, from a CODEC should be the only method used. The one recipient should only be a recording/streaming server. The best method for streaming to a number of recipients is to use a recording/streaming/web server where media can be encrypted and DoD compliant access control and auditing can be enforced via individual (unicast) viewer sessions with the server. IP multicast or broadcast should not be used. In the event IP multicast must be used, the media stream must be encrypted and a secure key exchange process employed. Full DoD compliant access control and auditing is required to gain access to the .sdp file that contains the information required to decrypt the stream. Encryption will prevent a streaming client that does not require the .sdp file from viewing the content after accessing the stream.'
  desc 'check', '[IP];  Interview the IAO to validate compliance with the following requirement:
     
Ensure the following regarding VTC streaming: 
- Streaming of VTC content will not be implemented unless required to fulfill a specific, validated, authorized, and documented mission requirement.
- Streaming from a VTU/CODEC is to the unicast addresses of a streaming/recording server only, not to an IP multicast or broadcast address due to the lack of user/recipient access control. 
- A streaming server is used that provides the streaming service via an authenticated and audited client to server (unicast) session or authenticated and audited access to an .sdp file.
- Streaming server access control will use DoD PKI.
- Streaming server to client connection is encrypted for confidentiality of the streamed media.
- If approved, and IP multicast must be used, the media stream must be encrypted and a secure key exchange process employed. 

Determine if VTC media streaming is being used. If not, this is not a finding. If so, additionally determine the following:
- Inspect the documentation regarding the validated and authorized/approved mission requirement. This is a finding if the documentation or approval is deficient or non-existent. 
- If IP multicast or IP broadcast is being used as the distribution method. If so, this is a finding unless the use is approved (inspect DAA approval documentation) and the media stream is encrypted and a secure key exchange process employed. 
- If streaming from a CODEC is being used, this is a finding if the media stream is not limited to the single IP address of a streaming/recording server.  
- If a streaming server is being used, this is a finding if the stream is not delivered via an authenticated and audited client to server (unicast) session or authenticated and audited access to an .sdp file; and/or Streaming server access control does not use DoD PKI; and/or the server to client connection is not encrypted.'
  desc 'fix', '[IP]; Perform the following tasks:
- Discontinue the use of VTC media streaming OR obtain approval for the validated mission requirement, the distribution method, and fully document the requirement, distribution method, and the approval.
- If streaming from a CODEC is approved, configure the codec for a unicast connection such that the media stream is limited to the single IP address of a streaming/recording server.  
- If IP multicast or IP broadcast is approved as the distribution method. Configure the streaming server/CODEC to encrypt the media stream and use a  secure key exchange process.
- If streaming from a streaming/recording server is approved, configure the server to provide the streaming service via an authenticated and audited client to server (unicast) session or authenticated and audited access to an .sdp file; additionally configure the server to use DoD PKI for access control; and to provide an encrypted client server connection or encryption of the media stream.'
  impact 0.5
  ref 'DPMS Target VTC Endpoint Site/System/Enclave'
  tag check_id: 'C-17358r1_chk'
  tag severity: 'medium'
  tag gid: 'V-16560'
  tag rid: 'SV-17559r1_rule'
  tag stig_id: 'RTS-VTC 2340.00'
  tag gtitle: 'RTS-VTC 2340.00 [IP]'
  tag fix_id: 'F-16528r1_fix'
  tag 'documentable'
  tag severity_override_guidance: 'NONE'
  tag potential_impacts: 'The inadvertent or improper disclosure of sensitive or classified information to a caller of a VTU that may not have an appropriate need-to-know or proper security clearance.'
  tag responsibility: ['Information Assurance Manager', 'Information Assurance Officer']
end
