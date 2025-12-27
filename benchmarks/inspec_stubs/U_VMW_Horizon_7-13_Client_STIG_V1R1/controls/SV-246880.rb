control 'SV-246880' do
  title 'The Horizon Client must use approved ciphers.'
  desc 'The Horizon Client disables the older TLS v1.0 protocol and the SSL v2 and SSL v3 protocols by default. TLS v1.1 is still enabled in the default configuration, despite known shortcomings, for the sake of backward compatibility with older servers and clients. The Horizon Connection Server STIG mandates TLS v1.2 in order to protect sensitive data-in-flight and the Client must follow suite.

Note: Mandating TLS 1.2 may affect certain thin and zero clients. Test and implement carefully.'
  desc 'check', 'Ensure the vdm_agent*.admx templates are added. Open the "Group Policy Management" MMC snap-in. Open the site-specific GPO applying Horizon settings to the VDI desktops.

Navigate to Computer Configuration >> Policies >> Administrative Templates >> VMware Horizon Client Configuration >> Security Settings. Double-click "Configures SSL protocols and cryptographic algorithms".

If "Configures SSL protocols and cryptographic algorithms" is set to "Disabled" or "Not Configured", this is a finding.

If the field beneath "Configures SSL protocols and cryptographic algorithms", is not set to "TLSv1.2:!aNULL:kECDH+AESGCM:ECDH+AESGCM:RSA+AESGCM:kECDH+AES:ECDH+AES:RSA+AES", this is a finding.'
  desc 'fix', 'Ensure the vdm_agent*.admx templates are added. Open the "Group Policy Management" MMC snap-in. Open the site-specific GPO applying Horizon settings to the VDI desktops.

Navigate to Computer Configuration >> Policies >> Administrative Templates >> VMware Horizon Client Configuration >> Security Settings. Double-click "Configures SSL protocols and cryptographic algorithms".

Make sure the setting is "Enabled".

In the field beneath "Configures SSL protocols and cryptographic algorithms", type the following:

TLSv1.2:!aNULL:kECDH+AESGCM:ECDH+AESGCM:RSA+AESGCM:kECDH+AES:ECDH+AES:RSA+AES

Click "OK".'
  impact 0.5
  ref 'DPMS Target VMware Horizon 7.13 Client'
  tag check_id: 'C-50312r768598_chk'
  tag severity: 'medium'
  tag gid: 'V-246880'
  tag rid: 'SV-246880r768600_rule'
  tag stig_id: 'HRZC-7X-000006'
  tag gtitle: 'SRG-APP-000516-AS-000237'
  tag fix_id: 'F-50266r768599_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
