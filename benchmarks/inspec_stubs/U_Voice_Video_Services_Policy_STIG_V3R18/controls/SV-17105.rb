control 'SV-17105' do
  title 'An unapproved Instant Messaging (IM) or Unified Capabilities (UC) soft client must not be used on Government Furnished Equipment (GFE).'
  desc 'DoD policies disallow general PC users from installing any unapproved application on their workstations or from attaching any unapproved or non-government furnished devices to them. Other DoD policies require users of GFE to limit their use to official business and not use them for personal business or other personal activities. Installation of VoIP and IM clients that associate themselves with, and connect to a public VoIP or IM service places the DoD system on which the client is installed at risk of, and provides an avenue for, its compromise and unauthorized access. Once compromised, the system could be used as a launching point for further compromise of the network or other DoD systems. Additionally, the use of these services also places the confidentiality of DoD information conveyed by them at risk. Such information could be sensitive or the collection of non-sensitive information over time could reveal sensitive information. Some services use standard ports 80 and 443 for web services which are generally never blocked.'
  desc 'check', 'Review site documentation to confirm a policy and procedure prevents an unapproved IM or UC soft client from being used on GFE. Prohibited clients and services include:
 - Yahoo Messenger
 - America Online (AOL) Instant Messenger (AIM)
 - Microsoft Network (MSN) Messenger
 - Skype
 - Freshtel
 - Google Hangouts (formerly Talk)
 - Magic Jack (A hardware USB ATA and UC soft client)
- Soft clients associated with home telephone service from carriers such as Verizon. AT&T, and Quest, cable carriers such as Comcast and Cox, or competing VoIP carriers such as Vonage.

If a policy and procedure does not prevent use of an unapproved IM or UC soft client on GFE, this is a finding. If unapproved clients or services are in use by site personnel, this is a finding.'
  desc 'fix', 'Implement site policy and procedure to prevent the use of unapproved IM or UC soft client on GFE. Uninstall all unapproved IM or UC soft clients on site GFE.'
  impact 0.5
  ref 'DPMS Target IP Voice/Video/UC Site / System'
  tag check_id: 'C-17161r3_chk'
  tag severity: 'medium'
  tag gid: 'V-16117'
  tag rid: 'SV-17105r2_rule'
  tag stig_id: 'VVoIP 1990'
  tag gtitle: 'VVoIP 1990'
  tag fix_id: 'F-16223r2_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
end
