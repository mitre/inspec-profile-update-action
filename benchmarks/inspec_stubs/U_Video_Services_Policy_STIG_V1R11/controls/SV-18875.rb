control 'SV-18875' do
  title 'Secure protocols must be implemented for CODEC remote control and management.'
  desc 'Many VTC Endpoints are remotely accessed across a network using nonsecure protocols such as telnet, FTP, and HTTP. This is a confidentiality issue since these protocols do not meet DoD requirements for password encryption while in transit. They also do not meet the encryption requirements for sensitive information in transit. Therefore, non-secure protocols should not be used. Some devices provide the option to select the secure versions of these protocols such as HTTPS and SSH for remote access. Secure protocols are required over non-secure protocols if available. 

Of additional concern is that remote control/management/configuration is performed in-band. In other words, it is performed using the same Ethernet port as the VTC traffic utilizes. If non-secure protocols must be utilized, the VTC production and CODEC remote access traffic must be segregated on the LAN from the normal data traffic. This is so that the confidentiality of the remote access password and sensitive management/configuration information is protected to the greatest extent possible by limiting access to it. Segregation requirements are discussed later under the LAN configuration section.'
  desc 'check', 'Review site documentation to confirm a policy and procedure requires secure protocols is implemented for CODEC remote control and management. Ensure secure remote access protocols, such as HTTPS and SSH, are used for CODEC remote control, management, and configuration. If secure protocols are not implemented for CODEC remote control and management, this is a finding. 

Note: During APL testing if the device does not support encrypted management protocols or an encrypted VPN between the managing workstation and the managed device, this is a finding.'
  desc 'fix', 'Secure protocols must be implemented for CODEC remote control and management
Purchase and implement VTC CODECs and other VTC devices that support encryption of “Remote Control/Management/Configuration” protocols via the use of encrypted protocols or encrypted VPN tunnels between the managing PC/workstation and the managed device. 
AND
Configure VTC CODECs and other VTC devices to use encrypted “Remote Control/Management/Configuration” protocols or an encrypted VPN tunnel between the managing PC/workstation/server and the managed device.'
  impact 0.5
  ref 'DPMS Target VTC Endpoint Site/System/Enclave'
  tag check_id: 'C-18971r2_chk'
  tag severity: 'medium'
  tag gid: 'V-17701'
  tag rid: 'SV-18875r2_rule'
  tag stig_id: 'RTS-VTC 3120.00'
  tag gtitle: 'RTS-VTC 3120'
  tag fix_id: 'F-17598r2_fix'
  tag 'documentable'
  tag severity_override_guidance: 'Reduced to no finding when unencrypted management protocols are passed through an encrypted VPN between the managing workstation and the managed device.'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
end
