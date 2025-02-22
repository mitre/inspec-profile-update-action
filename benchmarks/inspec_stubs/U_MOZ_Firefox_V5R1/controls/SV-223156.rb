control 'SV-223156' do
  title 'Firefox automatically executes or downloads MIME types which are not authorized for auto-download.'
  desc 'The default action for file types for which a plugin is installed is to automatically download and execute the file using the associated plugin. Firefox allows you to change the specified download action so that the file is opened with a selected external application or saved to disk instead. View the list of installed browser plugins and related MIME types by entering about:plugins in the address bar. 

When you click a link to download a file, the MIME type determines what action Firefox will take. You may already have a plugin installed that will automatically handle the download, such as Windows Media Player or QuickTime. Other times, you may see a dialog asking whether you want to save the file or open it with a specific application. When you tell Firefox to open or save the file and also check the option to "Do this automatically for files like this from now on", an entry appears for that type of file in the Firefox Applications panel, shown below.'
  desc 'check', %q(Use Method 1 or 2 to check if the following extensions are listed in the browser configuration:  HTA, JSE, JS, MOCHA, SHS, VBE, VBS, SCT, WSC.   By default, most of these extensions will not show up on the Firefox listing. 

Criteria: 

Method 1: In about:plugins, Installed plug-in, inspect the entries in the Suffixes column. 

If any of the prohibited extensions are found, then for each of them, verify that it is not associated with an application that executes code. However, applications such as Notepad.exe that do not execute code may be associated with the extension.  If the extension is associated with an unauthorized application, then this is a finding.

If the extension exists but is not associated with an application, then this is a finding. 

Method 2: 
Use the Options User Interface Applications menu  to search for the prohibited extensions in the Content column of the table.

If an extension that is not approved for automatic execution exists and the entry in the Action column is associated with an application that does not execute the code (e.g., Notepad), then do not mark this as a finding. 

If the entry exists and the "Action" is 'Save File' or 'Always Ask',  then this is not a finding.
 
If an extension exists and the entry in the Action column is associated with an application that does/can execute the code, then this is a finding.)
  desc 'fix', 'Remove any unauthorized extensions from the autodownload list.'
  impact 0.5
  ref 'DPMS Target Mozilla Firefox'
  tag check_id: 'C-24829r531285_chk'
  tag severity: 'medium'
  tag gid: 'V-223156'
  tag rid: 'SV-223156r612236_rule'
  tag stig_id: 'DTBF100'
  tag gtitle: 'SRG-APP-000278'
  tag fix_id: 'F-24817r531286_fix'
  tag 'documentable'
  tag legacy: ['SV-16709', 'V-15770']
  tag cci: ['CCI-001242']
  tag nist: ['SI-3 c 1']
end
