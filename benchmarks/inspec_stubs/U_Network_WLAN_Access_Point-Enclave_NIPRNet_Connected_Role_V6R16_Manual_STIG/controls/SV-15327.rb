control 'SV-15327' do
  title 'Network devices must authenticate all NTP messages received from NTP servers and peers.'
  desc %q(Since NTP is used to ensure accurate log file time stamp information, NTP could pose a security risk if a malicious user were able to falsify NTP information. To launch an attack on the NTP infrastructure, a hacker could inject time that would be accepted by NTP clients by spoofing the IP address of a valid NTP server. To mitigate this risk, the time messages must be authenticated by the client before accepting them as a time source. 

Two NTP-enabled devices can communicate in either client-server mode or peer-to-peer mode (aka "symmetric mode"). The peering mode is configured manually on the device and indicated in the outgoing NTP packets. The fundamental difference is the synchronization behavior: an NTP server can synchronize to a peer with better stratum, whereas it will never synchronize to its client regardless of the client's stratum. From a protocol perspective, NTP clients are no different from the NTP servers. The NTP client can synchronize to multiple NTP servers, select the best server and synchronize with it, or synchronize to the averaged value returned by the servers.

A hierarchical model can be used to improve scalability. With this implementation, an NTP client can also become an NTP server providing time to downstream clients at a higher stratum level and of decreasing accuracy than that of its upstream server. To increase availability, NTP peering can be used between NTP servers. In the event the device loses connectivity to its upstream NTP server, it will be able to choose time from one of its peers. 

The NTP authentication model is opposite of the typical client-server authentication model. NTP authentication enables an NTP client or peer to authenticate time received from their servers and peers. It is not used to authenticate NTP clients because NTP servers do not care about the authenticity of their clients, as they never accept any time from them.)
  desc 'check', 'Review the network element configuration and verify that it is authenticating NTP messages received from the NTP server or peer using a FIPS-approved message authentication code algorithm. FIPS-approved algorithms for authentication are the cipher-based message authentication code (CMAC) and the keyed-hash message authentication code (HMAC). AES and 3DES are NIST-approved CMAC algorithms. The following are NIST-approved HMAC algorithms: SHA-1, SHA-224, SHA-256, SHA-384, SHA-512, SHA-512/224, and SHA-512/256.

Downgrade:
If the network device is not capable of authenticating the NTP server or peer using a FIPS-approved message authentication code algorithm, then MD5 can be utilized for NTP message authentication and the finding can be downgraded to a CAT III.

If the network element is not configured to authenticate received NTP messages using a FIPS-approved message authentication code algorithm, this is a finding. A downgrade can be determined based on the criteria above.'
  desc 'fix', 'Configure the device to authenticate all received NTP messages using a FIPS-approved message authentication code algorithm.'
  impact 0.5
  ref 'DPMS Target Wireless Access Point'
  ref 'DPMS Target Network Appliance'
  tag check_id: 'C-12793r9_chk'
  tag severity: 'medium'
  tag gid: 'V-14671'
  tag rid: 'SV-15327r6_rule'
  tag stig_id: 'NET0813'
  tag gtitle: 'NTP messages are not authenticated.'
  tag fix_id: 'F-14132r4_fix'
  tag 'documentable'
end
