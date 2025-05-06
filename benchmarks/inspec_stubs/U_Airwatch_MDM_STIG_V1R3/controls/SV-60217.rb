control 'SV-60217' do
  title 'The AirWatch MDM Server must ensure authentication of both mobile device AirWatch MDM Server agent and server during the entire session.'
  desc 'AirWatch MDM Server can be prone to man-in-the middle attacks.  If communication sessions are not provided appropriate validity protections, such as the employment of SSL Mutual Authentication authenticity of the data cannot be guaranteed.'
  desc 'check', 'Review the AirWatch MDM Server configuration to ensure the AirWatch MDM Server ensures authentication of both mobile device AirWatch MDM Server agent and server during the entire session. If it does not, this is a finding.

AirWatch, upon native installation, activates a "Secure Channel" and generates root X.509 certificate to identify itself to devices and issue public keys to those devices for authentication. To verify Secure Channel is active: (1) click "Menu" from top tool bar, (2) click "System Configuration" under "Configuration" heading, (3) click "System" on left-hand tool bar, (4) click "Advanced", and (5) click "Secure Channel Certificate". (6) Ensure Secure Channel is enabled for applicable platforms and certificate is uploaded.'
  desc 'fix', 'Configure the AirWatch MDM Server to authenticate both the mobile device AirWatch MDM Server agent and server during the entire session.

To install AirWatch Secure Channel, please see "On-Premise Architecture Guide", page 26, "Appendix B - SSL Certificate Setup" for information on applying procured SSL certificates to the AirWatch MDM Server.

To enable SSL encryption: follow the applicable STIG detailing Microsoft server procedures for procuring and binding SSL Certificates.'
  impact 0.5
  ref 'DPMS Target AirWatch MDM 6.5'
  tag check_id: 'C-50111r2_chk'
  tag severity: 'medium'
  tag gid: 'V-47345'
  tag rid: 'SV-60217r1_rule'
  tag stig_id: 'ARWA-02-000226'
  tag gtitle: 'SRG-APP-219-MDM-160-MDM'
  tag fix_id: 'F-51051r2_fix'
  tag 'documentable'
  tag cci: ['CCI-001184']
  tag nist: ['SC-23']
end
