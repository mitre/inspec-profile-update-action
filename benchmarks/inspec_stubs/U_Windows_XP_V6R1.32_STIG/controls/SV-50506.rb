control 'SV-50506' do
  title 'The Enhanced Mitigation Experience Toolkit (EMET) Protection Profile for All (V3.0) or Popular Software (V4.0) must be implemented.'
  desc 'Attackers are constantly looking for vulnerabilities in systems and applications.  The Enhanced Mitigation Experience Toolkit can enable several mechanisms, such as Data Execution Prevention (DEP) on the system and applications adding additional levels of protection.'
  desc 'check', 'EMET 3.0
Verify the "All" Protection Profile has been implemented.  This implements mitigations to protect Internet Explorer, Office programs, and numerous third party applications.

If the following registry subkeys do not exist, this is a finding.

Registry Hive: HKEY_LOCAL_MACHINE
Path:  \\Software\\Microsoft\\EMET\\

The subkeys will include the following: 
7z.exe
7zfm.exe
7zg.exe
acrobat.exe
acrord32.exe
chrome.exe
communicator.exe
excel.exe
firefox.exe
googletalk.exe
iexplorer.exe
infopath.exe
itunes.exe
java.exe
javaw.exe
javaws.exe
mirc.exe
moe.exe
msaccess.exe
msnmsgr.exe
mspub.exe
msworks.exe
opera.exe
outlook.exe
photoshop.exe
pidgin.exe
plugin-container.exe
powerpnt.exe
pptview.exe
quicktimeplayer.exe
rar.exe
realconverter.exe
realplay.exe
safari.exe
skype.exe
thunderbird.exe
unrar.exe
visio.exe
vlc.exe
vpreview.exe
winamp.exe
windowslivesync.exe
windowslivewriter.exe
winrar.exe
winword.exe
winzip32.exe
winzip64.exe
wkscal.exe
wkscalrem.exe
wlsync.exe
wmplayer.exe

EMET 4.0
Verify the "Popular Software" Protection Profile has been implemented.  This implements mitigations to protect Internet Explorer, Office programs, and numerous third party applications.

If the following registry subkeys do not exist, this is a finding.

Registry Hive: HKEY_LOCAL_MACHINE
Path:  \\Software\\Microsoft\\EMET\\

The subkeys will include the following: 
7z.exe
7zfm.exe
7zg.exe
acrobat.exe
acrord32.exe
chrome.exe
communicator.exe
excel.exe
firefox.exe
foxit reader.exe
googletalk.exe
iexplore.exe
infopath.exe
itunes.exe
java.exe
javaw.exe
javaws.exe
lync.exe
mirc.exe
msaccess.exe
mspup.exe
ois.exe
opera.exe
outlook.exe
photoshop.exe
pidgen.exe
plugin-container.exe
powerpnt.exe
pptview.exe
quicktimeplayer.exe
rar.exe
realconverter.exe
realplay.exe
safari.exe
skydrive.exe
skype.exe
thunderbird.exe
unrar.exe
visio.exe
vlc.exe
vpreview.exe
winamp.exe
windowslivewriter.exe
winrar.exe
winword.exe
winzip32.exe
winzip64.exe
wlmail.exe
wlxphotogallery.exe
wmplayer.exe
wordpad.exe

Additional details of the implementation can be viewed with the following.
Open a command prompt.
Navigate to the EMET installation directory, typically \\Program Files\\EMET.
Execute the following command - "EMET_Conf --list".'
  desc 'fix', %q(EMET 3.0
Open a command prompt.
Navigate to the EMET installation directory, typically \Program Files\EMET.
Execute the following command -'EMET_Conf --import "deployment\protection profiles\all.xml"'

EMET 4.0
Open a command prompt.
Navigate to the EMET installation directory, typically \Program Files\EMET.
Execute the following command -'EMET_Conf --import "deployment\protection profiles\popular software.xml"'

The Enhanced Mitigation Experience Toolkit must be installed on the system to make this setting available.)
  impact 0.5
  ref 'DPMS Target Windows XP'
  tag check_id: 'C-46267r3_chk'
  tag severity: 'medium'
  tag gid: 'V-36704'
  tag rid: 'SV-50506r3_rule'
  tag stig_id: 'WINEM-000081'
  tag gtitle: 'WINCC-000081'
  tag fix_id: 'F-43654r2_fix'
  tag 'documentable'
  tag ia_controls: 'ECVP-1'
end
