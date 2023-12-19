control 'SV-17103' do
  title 'The integrity of VVoIP endpoint configuration files downloaded during endpoint registration must be validated using digital signatures.'
  desc 'During VVoIP endpoint registration with the session controller, a file is downloaded by the endpoint from the session manager containing specific configuration settings. This file contains the phone number assigned to the endpoint, the IP addresses for session management, the software menus specific to the system, the endpoint configuration password, the stored personal preferences and speed dial numbers, and other system operational information. These configuration settings can be updated by resetting and re-registering the endpoint, which causes an updated configuration file to be downloaded.

The integrity of these files is critical to preventing compromise of the Unified Capabilities (UC) soft clients, the hardware endpoints, and the system itself. The best method for maintaining configuration file integrity is requiring they be digitally signed. This prevents man-in-the-middle attacks where the configuration file could be modified in transit or the source of the file spoofed. Digital signatures and the file integrity must also be validated before the configuration file is used.'
  desc 'check', 'Review site documentation to confirm the integrity of VVoIP endpoint configuration files downloaded during endpoint registration is validated using digital signatures. This is not applicable to hardware endpoints with a preinstalled configuration file and do not download a configuration file through the network. This is not applicable to UC soft clients that do not download a configuration file through the network. If the VVoIP endpoint configuration files downloaded during endpoint registration are not digitally signed, this is a finding. If the VVoIP endpoint configuration files downloaded during endpoint registration are not validated using digital signatures, this is a finding.'
  desc 'fix', 'Implement and document the integrity of VVoIP endpoint configuration files downloaded during endpoint registration is validated using digital signatures. VVoIP endpoints must use DoD PKI certifications. This requirement does not apply to hardware endpoints or UC soft clients that do not download configuration files from the session manager.'
  impact 0.5
  ref 'DPMS Target IP Voice/Video/UC Site / System'
  tag check_id: 'C-17159r2_chk'
  tag severity: 'medium'
  tag gid: 'V-16115'
  tag rid: 'SV-17103r2_rule'
  tag stig_id: 'VVoIP 1935'
  tag gtitle: 'VVoIP 1935'
  tag fix_id: 'F-16221r2_fix'
  tag 'documentable'
  tag severity_override_guidance: 'Reduce to a CAT III when vendor generated certificates are used instead of DoD PKI certificates.'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
end
