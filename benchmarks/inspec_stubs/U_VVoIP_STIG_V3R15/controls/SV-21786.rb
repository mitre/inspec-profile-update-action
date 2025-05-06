control 'SV-21786' do
  title 'The implementation of Unified Mail services degrades the separation between the voice and data protection zones (VLANs).'
  desc 'Voice mail services in a VoIP environment are available in several different configurations. A legacy voice mail platform can connect to a VoIP environment to provide voice mail services for VoIP users. In the same respect, a VoIP voice mail platform can provide voice mail services to the legacy voice users and the VoIP users. Some voice mail systems are also capable of providing unified mail by interacting with email messaging systems. Voicemails when recorded are converted to a .wav or similar digital audio file and sent to the email server as an attachment to an email. The subject line will typically contain the caller ID information if available. The email user can then open the attachment and listen to the voicemail on their PC or whatever device that provides properly authenticated access to the user’s email. 

Since the voicemail server must access the voice network (which, in a VoIP system is the VoIP VLAN system), and the data network (data VLANs) to send the email, caution and control must be exercised to not degrade the separation between the voice and data VLANs. Additionally, if the email server is part of or collocated with the voicemail server, user access to email must also not degrade the separation between the voice and data VLANs. Since this server may have 2 NICs and be connected to both voice and data VLANs, the server must not act as a bridge between the voice and data VLANs.'
  desc 'check', 'Interview the IAO to confirm compliance with the following requirement: Ensure the implementation of a unified mail system does not degrade the separation and traffic filtering between the voice and data security zones or VLANs. 

This is a finding in the event the sending of voicemails to an email server or user access to email degrades the separation between the voice and data VLAN(s) such that the hosts or users on the data VLAN(s) have easy access to the VoIP instruments, traffic and infrastructure hosts on the VoIP VLAN(s).'
  desc 'fix', 'Ensure the implementation of a unified mail system does not degrade the separation and traffic filtering between the voice and data security zones or VLANs. 

Configure unified mail services with access to both the data and voice VLANs to NOT bridge the two environments together.'
  impact 0.5
  ref 'DPMS Target VVoiP Device'
  tag check_id: 'C-23991r1_chk'
  tag severity: 'medium'
  tag gid: 'V-19645'
  tag rid: 'SV-21786r2_rule'
  tag stig_id: 'VVoIP 5560'
  tag gtitle: "Deficient imp'n: UM degrades voice/data separation"
  tag fix_id: 'F-20349r1_fix'
  tag 'documentable'
end
