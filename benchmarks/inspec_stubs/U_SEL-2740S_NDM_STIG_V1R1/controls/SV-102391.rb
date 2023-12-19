control 'SV-102391' do
  title 'The SEL-2740S must be adopted by OTSDN Controllers for secure communication identifiers and initial trust for configuration of remote maintenance and diagnostic communications.'
  desc 'This requires the use of secure protocols instead of their unsecured counterparts, such as SSH instead of telnet, SCP instead of FTP, and HTTPS instead of HTTP. If unsecured protocols (lacking cryptographic mechanisms) are used for sessions, the contents of those sessions will be susceptible to eavesdropping, potentially putting sensitive data (including administrator passwords) at risk of compromise and potentially allowing hijacking of maintenance sessions.'
  desc 'check', %q(To ensure SEL-2740's credentials and identifiers are accurate, do the following:
1. Log in with Admin rights into parent OTSDN Controller.
2. Download the latest settings for the SEL-2740S device under test (DUT).
3. Go to the "Administration" page.
4. Go to the "X.509 Entries" page.
5. Check that each certificate is necessary, status is valid and reconcile with the parent OTSDN controller(s) for the network.  

If the SEL-2740S is not configured with the proper X.509 certificates or contains unnecessary certificate entries, this is a finding.)
  desc 'fix', 'To configure the SEL-2740S X.509 certificate for TLS communications, the device needs to be simply adopted by OTSDN controller.
Before adopting, create an SEL-2740S configuration node object. 

To adopt an SEL-2740S do the following:
1. Go to the "Topology" page.
2. Select the SEL-2740S you want to adopt. The Option window shows the SEL-2740S Node Options pane.
3. Select the SEL-2740S configuration node from the "Configuration" setting. The "Adopt Configuration" button is enabled.
4. Click the "Adopt Configuration" button. The Feedback bar displays "Success" to indicate successful application of the configuration node. The adoption process starts.
5. Wait until the alarm contact pulses (about 30 to 60 seconds). After clicking the Adopt button, the process may take a minute or longer to complete depending on the speed of the SEL-5056 host machine. When complete, the selected object becomes adopted, the appropriate ports appear, and the Adoption State is "Adopted".'
  impact 0.7
  ref 'DPMS Target SEL SDN Switch NDM'
  tag check_id: 'C-91599r1_chk'
  tag severity: 'high'
  tag gid: 'V-92303'
  tag rid: 'SV-102391r1_rule'
  tag stig_id: 'SELS-ND-001180'
  tag gtitle: 'SRG-APP-000412-NDM-000331'
  tag fix_id: 'F-98541r1_fix'
  tag 'documentable'
  tag cci: ['CCI-003123']
  tag nist: ['MA-4 (6)']
end
