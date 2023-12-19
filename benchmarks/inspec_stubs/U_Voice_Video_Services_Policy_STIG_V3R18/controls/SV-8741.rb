control 'SV-8741' do
  title 'Access to personal voice mail settings by the subscriber via an IP connection is not secured via encryption and/or web” server on the voicemail system is not configured in accordance with the “private web server” requirements in the Web Server STIG/Checklist.'
  desc 'In traditional TDM phone systems, personal voicemail settings and greetings are accessed / configured by the subscriber/user on traditional voicemail servers via the traditional telephone. Control commands are dialed using the keypad and transmitted using Dial-Tone Multi-Frequency (DTMF) audio tones. The voice greetings are transmitted using normal audio as well. The audio can be analog or digital, which is encoded in whatever coding scheme is used by the local PBX. In IP based phone systems access to the voicemail server carries the same vulnerabilities as the IP voice communications carried by the system. As such access to voicemail for the purpose of creating greeting messages, retrieving voicemail, or adjusting personal settings, must be encrypted on the IP network. In part this is because anyone with a sniffer and access to the right LAN segment can acquire the subscriber’s account and password information. With this intercepted information a hacker could gain access to the subscribers voice mail account, intercept sensitive information, and/or perform other destructive actions. Once access to settings is achieved there the intruder could change greetings or possibly forward all voicemails received.

Encryption of the voice message traffic as well as control from the phone’s dial-pad falls under the normal requirement for the encryption of VoIP signaling and media.

In the event the subscriber’s personal settings are accessible via a “web” connection using a browser on the subscriber’s desktop or phone, the connection must use HTTPS and TLS minimally to protect the user’s logon credentials. Additionally, the voicemail system/server, which provides this service via a web server application, must be configured in accordance with the “private web server” requirements in the Web Server STIG/Checklist.'
  desc 'check', 'Interview the IAO to validate compliance with the following requirement: In the event voicemail subscribers can access their voicemail settings via an IP or “web” connection (in addition to having the standard normal capability from the phone via the dial pad), ensure the connection is encrypted using HTTPS with TLS. Additionally, ensure the web server on the voicemail system/server is configured in accordance with “private web server” requirements in the Web Services STIG/Checklist.

NOTE: Web Services STIG/Checklist requirements include but are not limited to user CAC/PKI authentication

Inspect the Web SRR results from the web server review performed on the web based personal settings interface to the voicemail system. If there is none, perform a Web SRR. This check is not intended to determine if the asset is in full compliance, it is only to determine if the applicable STIG has been applied.

This is a finding in the event the voicemail system provides a web interface that is either not configured in accordance with the applicable Web STIG/Checklist requirements and/or it does not the web interface does not use HTTPS/TLS.'
  desc 'fix', 'Configure the voicemail system web access to personal settings in accordance with the applicable private web server requirements in the Web STIG/Checklist and ensure web interface is configured to use HTTPS/TLS.'
  impact 0.5
  ref 'DPMS Target IP Voice/Video/UC Site / System'
  tag check_id: 'C-23710r1_chk'
  tag severity: 'medium'
  tag gid: 'V-8255'
  tag rid: 'SV-8741r1_rule'
  tag stig_id: 'VVoIP 1520 (GENERAL)'
  tag gtitle: 'Deficient security: Personal VM settings via web'
  tag fix_id: 'F-20188r1_fix'
  tag 'documentable'
  tag severity_override_guidance: 'None'
  tag potential_impacts: 'Denial of Service and/or unauthorized access to network or voice system resources or services and the information they contain. Application of features and potential call redirection by unauthorized users.'
  tag responsibility: 'Information Assurance Officer'
end
