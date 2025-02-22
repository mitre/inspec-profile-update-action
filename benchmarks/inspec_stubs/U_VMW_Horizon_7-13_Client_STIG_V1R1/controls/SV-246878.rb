control 'SV-246878' do
  title 'The Horizon Client must not ignore certificate revocation problems.'
  desc 'When the Horizon Client connects to the server, by default, the server TLS certificate will be validated on the client side. If the revocation status cannot be determined or if the certificate is revoked, the connection will fail due to an untrusted connection. This default behavior can be overridden, however, to ignore revocation errors and proceed with revoked or certificates of unknown status. The default, secure, configuration must be validated and maintained.'
  desc 'check', 'Ensure the vdm_agent*.admx templates are added. Open the "Group Policy Management" MMC snap-in. Open the site-specific GPO applying Horizon settings to the VDI desktops.

Navigate to Computer Configuration >> Policies >> Administrative Templates >> VMware Horizon Client Configuration >> Security Settings. Double-click "Ignore certificate revocation problems".

If "Ignore certificate revocation problems" is set to "Enabled", this is a finding.'
  desc 'fix', 'Ensure the vdm_agent*.admx templates are added. Open the "Group Policy Management" MMC snap-in. Open the site-specific GPO applying Horizon settings to the VDI desktops.

Navigate to Computer Configuration >> Policies >> Administrative Templates >> VMware Horizon Client Configuration >> Security Settings. Double-click "Ignore certificate revocation problems".

Make sure the setting is "Disabled". Click "OK".'
  impact 0.5
  ref 'DPMS Target VMware Horizon 7.13 Client'
  tag check_id: 'C-50310r768592_chk'
  tag severity: 'medium'
  tag gid: 'V-246878'
  tag rid: 'SV-246878r768594_rule'
  tag stig_id: 'HRZC-7X-000004'
  tag gtitle: 'SRG-APP-000516-AS-000237'
  tag fix_id: 'F-50264r768593_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
