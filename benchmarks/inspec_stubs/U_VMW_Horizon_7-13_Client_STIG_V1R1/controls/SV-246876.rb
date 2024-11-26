control 'SV-246876' do
  title 'The Horizon Client must not connect to servers without fully verifying the server certificate.'
  desc 'Preventing the disclosure of transmitted information requires that the application server take measures to employ some form of cryptographic mechanism in order to protect the information during transmission.  This is usually achieved through the use of Transport Layer Security (TLS).

The Horizon Client connects to the Connection Server, UAG or other gateway via a TLS connection. This initial connection must be trusted, otherwise the sensitive information flowing over the tunnel could potentially be open to interception. The Horizon Client can be configured to ignore any certificate validation errors, warn or fail. By default, the Client will warn and let the user decide to proceed or not. This decision must not be left to the end user. In a properly configured, enterprise environment, there should be no trouble with the presented certificate. On the other hand, a TLS connection could be easily intercepted and middle-manned with the assumption that a user will just click away any errors.'
  desc 'check', 'Ensure the vdm_agent*.admx templates are added. Open the "Group Policy Management" MMC snap-in. Open the site-specific GPO applying Horizon settings to the VDI desktops.

Navigate to Computer Configuration >> Policies >> Administrative Templates >> VMware Horizon Client Configuration >> Security Settings. Double-click "Certificate verification mode".

If "Certificate verification mode" is "Not Configured" or "Disabled", this is a finding.

If "Certificate verification mode" is not set to "Full Security", this is a finding.'
  desc 'fix', 'Ensure the vdm_agent*.admx templates are added. Open the "Group Policy Management" MMC snap-in. Open the site-specific GPO applying Horizon settings to the VDI desktops.

Navigate to Computer Configuration >> Policies >> Administrative Templates >> VMware Horizon Client Configuration >> Security Settings. Double-click "Certificate verification mode".

Make sure the setting is "Enabled".

In the dropdown below "Certificate verification mode", select "Full Security". Click "OK".'
  impact 0.5
  ref 'DPMS Target VMware Horizon 7.13 Client'
  tag check_id: 'C-50308r768586_chk'
  tag severity: 'medium'
  tag gid: 'V-246876'
  tag rid: 'SV-246876r768588_rule'
  tag stig_id: 'HRZC-7X-000002'
  tag gtitle: 'SRG-APP-000516-AS-000237'
  tag fix_id: 'F-50262r768587_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
