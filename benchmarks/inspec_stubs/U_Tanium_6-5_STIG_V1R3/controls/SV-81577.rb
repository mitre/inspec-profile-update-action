control 'SV-81577' do
  title 'Flash must not be installed on the Tanium Server.'
  desc 'Adobe Flash Player is freeware software for using content created on the Adobe Flash platform, including viewing multimedia, executing rich Internet applications, and streaming video and audio. 

Flash Player is a common format for games, animations, and graphical user interfaces (GUIs) embedded in web pages. 

Flash Player runs SWF files. Flash Player supports vector and raster graphics, 3D graphics, an embedded scripting language called ActionScript, and streaming of video and audio. ActionScript is based on ECMAScript, and supports object-oriented code, and is similar to JavaScript.Adobe Flash Player is a runtime that executes and displays content from a provided SWF file.  

Although it has no in-built features to modify the SWF file at runtime, it can execute software written in the ActionScript programming language which enables the runtime manipulation of text, data, vector graphics, raster graphics, sound, and video. The player can also access certain connected hardware devices, including web cameras and microphones, after permission for the same has been granted by the user.

Throughout the various version of Adobe Flash Player, multiple vulnerabilities have been exposed requiring patching to mitigate and because of these vulnerabilities it continues to be a target for exploitation.

Since Tanium does not require Adobe Flash Player for any functionality, ensuring it is not installed removes the vulnerability.'
  desc 'check', 'Access the Tanium Server interactively. Log on with an account with administrative privileges to the server.

Access Settings >> Control Panel >> Programs >> Programs and Features.

Review the installed programs.

If Adobe Flash Player is installed, this is a finding.'
  desc 'fix', 'Access the Tanium Server interactively. Log on with an account with administrative privileges to the server.

Access Settings >> Control Panel >> Programs >> Programs and Features.

Click on the Adobe Flash Player to select it.

Select “Uninstall”.'
  impact 0.5
  ref 'DPMS Target Tanium 6.5'
  tag check_id: 'C-67723r1_chk'
  tag severity: 'medium'
  tag gid: 'V-67087'
  tag rid: 'SV-81577r1_rule'
  tag stig_id: 'TANS-SV-000022'
  tag gtitle: 'SRG-APP-000210'
  tag fix_id: 'F-73187r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001170']
  tag nist: ['SC-18 (4)']
end
