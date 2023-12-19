control 'SV-21552' do
  title 'The confidentiality of VVoIP endpoint configuration files downloaded during endpoint registration must be protected by encryption.'
  desc 'During VVoIP endpoint registration with the session controller, a file is downloaded by the endpoint from the session manager containing specific configuration settings. This file contains the phone number assigned to the endpoint, the IP addresses for session management, the software menus specific to the system, the endpoint configuration password, the stored personal preferences and speed dial numbers, and other system operational information. These configuration settings can be updated by resetting and re-registering the endpoint, which causes an updated configuration file to be downloaded.

The confidentiality of these files is critical to preventing compromise of the Unified Capabilities (UC) soft clients, the hardware endpoints, and the system itself. Some configuration files may be human readable like XML code and most VVoIP signaling protocols. When human readable, intelligence can be gathered by capturing the file in transit. The best method for maintaining the confidentiality of configuration files is encryption. This prevents man-in-the-middle attacks. Encryption of this file is also required if the file contains the password used to access the endpoint’s configuration information and settings menus.'
  desc 'check', 'Review site documentation to confirm the confidentiality of endpoint configuration files downloaded during endpoint registration is protected. This is not applicable to hardware endpoints with a preinstalled configuration file and do not download a configuration file through the network. This is not applicable to UC soft clients that do not download a configuration file through the network. If configuration files are in a vendor specific binary format only interpretable by the vendor’s endpoints, this is not a finding. If the confidentiality of endpoint configuration files downloaded during endpoint registration is not encrypted, this is a finding.'
  desc 'fix', 'Implement and document the confidentiality of VVoIP endpoint configuration files downloaded during endpoint registration is protected by encryption. This requirement does not apply to hardware endpoints or UC soft clients that do not download configuration files from the session manager.'
  impact 0.3
  ref 'DPMS Target IP Voice/Video/UC Site / System'
  tag check_id: 'C-23776r2_chk'
  tag severity: 'low'
  tag gid: 'V-19493'
  tag rid: 'SV-21552r2_rule'
  tag stig_id: 'VVoIP 1936'
  tag gtitle: 'VVoIP 1936'
  tag fix_id: 'F-20214r2_fix'
  tag 'documentable'
end
