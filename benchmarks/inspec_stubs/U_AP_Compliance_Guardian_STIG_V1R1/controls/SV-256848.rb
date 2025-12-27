control 'SV-256848' do
  title 'Compliance Guardian must only allow the use of DOD PKI established certificate authorities for verification of the establishment of protected sessions.'
  desc 'Untrusted Certificate Authorities (CAs) can issue certificates, but they may be issued by organizations or individuals that seek to compromise DOD systems or by organizations with insufficient security controls. If the CA used for verifying the certificate is not a DOD-approved CA, trust of this CA has not been established.

The DOD will only accept PKI certificates obtained from a DOD-approved internal or external certificate authority. Reliance on CAs for the establishment of secure sessions includes the use of TLS certificates.

This requirement focuses on communications protection for the application session rather than for the network packet.

This requirement applies to applications that utilize communications sessions. This includes, but is not limited to, web-based applications and Service-Oriented Architectures (SOA).'
  desc 'check', 'There are three different settings in Compliance Guardian that are related to certificates.
1. The Compliance Guardian web server for the web UI.
2. The Compliance Guardian Manager communication certificate for communicating with Compliance Guardian Agents.
3. The Compliance Guardian Agent communication certificate for communicating with Compliance Guardian Manager.

1. Check the Compliance Guardian Web Site certificate setting.
- On the Compliance Guardian Manager server, open Internet Information Services (IIS) Manager.
- In IIS Manager, expand the Sites node in the Connections panel on the left and find Compliance Guardian Web Site. The default name of Compliance Guardian Control Web Site is ComplianceGuardian4Site.
- Click "Bindings" in the Actions panel on the right to open the "Site Bindings" window.
- Click "Edit" in Site Bindings window to open the "Edit Site Binding" window.
- Verify the certificate information.

If the certificate used is not a DOD- or AO-approved certificate, this is a finding.

2. Check the Compliance Guardian Manager communication certificate setting.
- On the Compliance Guardian Manager server, open Compliance Guardian Manager Configuration Tool.
- Click "Advanced Configuration" on the left.
- Verify the certificate information.

If the certificate used is not a DOD-approved certificate, this is a finding.

3. Check the Compliance Guardian Agent communication certificate setting.
- On the Compliance Guardian Agent server, open Compliance Guardian Agent Configuration Tool.
- Navigate to the SSL Certificate panel.
- Verify the certificate information.

If the certificate used is not a DOD-approved certificate, this is a finding.'
  desc 'fix', 'Configure Compliance Guardian to ensure that it uses PKI certificates obtained from a DOD-approved internal or external certificate authority. There are three different settings in Compliance Guardian that are related to certificates.
1. The Compliance Guardian web server for the web UI.
2. The Compliance Guardian Manager communication certificate for communicating with Compliance Guardian Agents.
3. The Compliance Guardian Agent communication certificate for communicating with Compliance Guardian Manager.

1. Configure the Compliance Guardian Web Site certificate setting.
- On the Compliance Guardian Manager server, open Internet Information Services (IIS) Manager.
- In IIS Manager, expand the Sites node in the Connections panel on the left and find Compliance Guardian Control Web Site. The default name of Compliance Guardian Control Web Site is ComplianceGuardian4Site.
- Click "Bindings" in the Actions panel on the right to open the "Site Bindings" window.
- Click "Edit" in Site Bindings window to open the "Edit Site Binding" window.
- Select the DOD-approved certificate.
- Click "OK" to save settings.

2. Configure the Compliance Guardian Manager communication certificate setting.
- On the Compliance Guardian Manager server, open Compliance Guardian Manager Configuration Tool.
- Click "Advanced Configuration" on the left.
- Click the "User-defined Certificate" radio button, then click "Select Certificate" to open the Windows Security window.
- Select the DOD-approved certificate.
- Click OK to save settings.

3. Configure the Compliance Guardian Agent communication certificate setting.
- On the Compliance Guardian Agent server, open Compliance Guardian Agent Configuration Tool.
- Navigate to the SSL Certificate panel.
- Click the "User-defined Certificate" radio button, then click "Select Certificate" button to open the Windows Security window.
- Select the DOD-approved certificate.
- Click OK to save settings.'
  impact 0.5
  ref 'DPMS Target AvePoint Compliance Guardian'
  tag check_id: 'C-60523r890152_chk'
  tag severity: 'medium'
  tag gid: 'V-256848'
  tag rid: 'SV-256848r890154_rule'
  tag stig_id: 'APCG-00-000045'
  tag gtitle: 'SRG-APP-000427'
  tag fix_id: 'F-60466r890153_fix'
  tag 'documentable'
  tag cci: ['CCI-002470']
  tag nist: ['SC-23 (5)']
end
