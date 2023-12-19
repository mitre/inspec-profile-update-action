control 'SV-75799' do
  title 'VVoIP endpoint configuration files must not be downloaded automatically during initial endpoint registration.'
  desc 'During VVoIP endpoint registration with the session controller, a file is downloaded by the endpoint from the session manager containing specific configuration settings. This file contains the phone number assigned to the endpoint, the IP addresses for session management, the software menus specific to the system, the endpoint configuration password, the stored personal preferences and speed dial numbers, and other system operational information. These configuration settings can be updated by resetting and re-registering the endpoint, which causes an updated configuration file to be downloaded.

Unregulated automatic download of VVoIP endpoint configuration files during initial registration allows rogue endpoints to become part of the system. It also potentially allows human readable configuration files to be sent without encryption or digital signatures.'
  desc 'check', 'Review site documentation to confirm the VVoIP endpoint configuration files are not downloaded automatically during initial endpoint registration. 

If VVoIP endpoint configuration files are downloaded automatically during initial endpoint registration, this is a finding.'
  desc 'fix', 'Implement a VVoIP system design preventing auto-download of VVoIP endpoint configuration files on initial deployment. Document the design, demonstrating that unregulated automatic download of VVoIP endpoint configuration files during initial registration is prevented.'
  impact 0.5
  ref 'DPMS Target IP Voice/Video/UC Site / System'
  tag check_id: 'C-62271r2_chk'
  tag severity: 'medium'
  tag gid: 'V-61319'
  tag rid: 'SV-75799r2_rule'
  tag stig_id: 'VVoIP 1937'
  tag gtitle: 'VVoIP 1937'
  tag fix_id: 'F-67219r2_fix'
  tag 'documentable'
end
