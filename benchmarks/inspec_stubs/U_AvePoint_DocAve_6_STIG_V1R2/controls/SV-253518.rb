control 'SV-253518' do
  title 'DocAve must only allow the use of DoD PKI-established certificate authorities for verification of the establishment of protected sessions.'
  desc 'Untrusted Certificate Authorities (CA) can issue certificates, but they may be issued by organizations or individuals that seek to compromise DoD systems or by organizations with insufficient security controls. If the CA used for verifying the certificate is not a DoD-approved CA, trust of this CA has not been established.

The DoD will only accept PKI certificates obtained from a DoD-approved internal or external certificate authority. Reliance on CAs for the establishment of secure sessions includes, for example, the use of TLS certificates. 

This requirement focuses on communications protection for the application session rather than for the network packet.

This requirement applies to applications that utilize communications sessions. This includes, but is not limited to, web-based applications and Service-Oriented Architectures (SOA).'
  desc 'check', 'There are three different settings in DocAve that are related to certificates:
- The DocAve web server for the web UI;
- The DocAve Manager communication certificate for communicate with DocAve Agents;
- The DocAve Agent communication certificate for communicate with DocAve Manager.

Check the DocAve Web Site certificate setting.
- On the DocAve 6 Manager server, open Internet Information Services (IIS) Manager.
- In IIS Manager, expand the Sites node in the Connections panel on the left and find DocAve 6 Control Service Web Site. The default name of DocAve Control Web Site is DocAve6.
- Click "Bindings" in the Actions panel on the right to open the Site Bindings window.
- Click "Edit" in Site Bindings window to open the Edit Site Binding window.
- Verify the certificate information.

If the certificate used is not a DoD- (or AO-) approved certificate, this is a finding.

Check the DocAve Manager communication certificate setting.
- On the DocAve 6 Manager server, open DocAve 6 Manager Configuration Tool.
- Click "Advanced Configuration" on the left.
- Verify the certificate information.

If the certificate used is not a DoD approved certificate, this is a finding.

Check the DocAve Agent communication certificate setting.
- On the DocAve 6 Agent server, open DocAve 6 Agent Configuration Tool.
- Navigate to the SSL Certificate panel.
- Verify the certificate information.

If the certificate used is not a DoD-approved certificate, this is a finding.'
  desc 'fix', 'Configure DocAve to ensure that it uses PKI certificates obtained from a DoD-approved internal or external certificate authority. There are three different settings in DocAve that are related to certificates:
- The DocAve web server for the web UI;
- The DocAve Manager communication certificate for communicate with DocAve Agents;
- The DocAve Agent communication certificate for communicate with DocAve Manager.

Configure the DocAve Web Site certificate setting.
- On the DocAve 6 Manager server, open Internet Information Services (IIS) Manager.
- In IIS Manager, expand the Sites node in the Connections panel on the left and find DocAve 6 Control Service Web Site. The default name of DocAve Control Web Site is DocAve6.
- Click "Bindings" in the Actions panel on the right to open the Site Bindings window.
- Click "Edit" in Site Bindings window to open the Edit Site Binding window.
- Select the DoD-approved certificate.
- Click "OK" to save settings.

Configure the DocAve Manager communication certificate setting.
- On the DocAve 6 Manager server, open DocAve 6 Manager Configuration Tool.
- Click "Advanced Configuration" on the left.
- Click the "User-defined Certificate" radio button, then click "Select Certificate" to open the Windows Security window.
- Select the DoD-approved certificate.
- Click "OK" to save settings.

Configure the DocAve Agent communication certificate setting.
- On the DocAve 6 Agent server, open DocAve 6 Agent Configuration Tool.
- Navigate to the SSL Certificate panel.
- Click the "User-defined Certificate" radio button, then click "Select Certificate" to open the Windows Security window.
- Select the DoD-approved certificate.
- Click "OK" to save settings.'
  impact 0.5
  ref 'DPMS Target AvePoint DocAve 6'
  tag check_id: 'C-56970r836527_chk'
  tag severity: 'medium'
  tag gid: 'V-253518'
  tag rid: 'SV-253518r836529_rule'
  tag stig_id: 'DCAV-00-000192'
  tag gtitle: 'SRG-APP-000427'
  tag fix_id: 'F-56921r836528_fix'
  tag 'documentable'
  tag cci: ['CCI-002470']
  tag nist: ['SC-23 (5)']
end
