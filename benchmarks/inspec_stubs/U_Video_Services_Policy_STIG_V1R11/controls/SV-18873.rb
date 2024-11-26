control 'SV-18873' do
  title 'A CODECs local Application Programmers Interface (API) must prevent unrestricted access to user or administrator configuration settings and CODEC controls without a password.'
  desc 'Large conference room VTC systems may be built into the conference room in such a way that a hand-held remote control cannot directly access or control the CODEC because it is located in another room such as an AV control room. While there are systems and methods for extending the control signals from the hand-held remote control to the CODEC, many times the CODEC is connected to an AV control panel (typically called a “touch panel”) that sits on the conference table or possibly a podium. While this panel can be connected to the CODEC wirelessly (as discussed later) or via a wired IP connection, typically the connection is via an EIA-232 serial connection on the CODEC. To give the “touch panel” the ability to control the CODEC, the CODEC contains an API control program. All functions that are available on the hand-held remote control are typically duplicated on the “touch panel”

Typically a VTC CODEC’s API provides full access to all configuration settings and control commands supported but the CODEC. This can be a big problem if the command channel is compromised because this would give the attacker the ability to reconfigure the CODEC or its features and capabilities and not just control them. To mitigate this problem, the CODEC’s API must provide a separation of the commands that control the system from the commands related to user and administrator configuration settings. If a password/PIN is implemented for user settings as required above, the touch panel must support the manual entry of the user configuration password/PIN assuming they will need to be accessed via the touch panel. Similarly, administrator settings should not be accessible from the touch panel or the interface on the CODEC that it uses without the use of an administrator password/PIN.'
  desc 'check', "Review site documentation to confirm a CODEC’s API does not provide unrestricted access to user or administrator configuration settings and without the use of an appropriate password.

Review the vendor documentation on the API. Look for information on restricting access to user or administrator configuration settings. Determine what user or administrator configuration settings are accessible or programmable via the API. Determine all API access methods and communications protocols, meaning local serial connection or “remotely” via a network.
AND
Establish a connection to the CODEC’s API using the information gained above and a PC; disconnect any AV control panel if necessary. Attempt to gain access and to change various user or administrator configuration settings via the API.

If a CODEC's local API does not prevent unrestricted access to user or administrator configuration settings and CODEC controls without a password, this is a finding."
  desc 'fix', "Implement only CODEC's with a local API preventing unrestricted access to user or administrator configuration settings and CODEC controls without a password."
  impact 0.5
  ref 'DPMS Target VTC Endpoint Site/System/Enclave'
  tag check_id: 'C-18969r2_chk'
  tag severity: 'medium'
  tag gid: 'V-17699'
  tag rid: 'SV-18873r3_rule'
  tag stig_id: 'RTS-VTC 2820.00'
  tag gtitle: 'RTS-VTC 2820'
  tag fix_id: 'F-17596r2_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
end
