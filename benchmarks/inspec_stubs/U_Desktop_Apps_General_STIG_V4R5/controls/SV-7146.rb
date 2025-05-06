control 'SV-7146' do
  title 'Open-restricted File Type Properties'
  desc 'For some file types, providing the user an opportunity to cancel the opening of the file provides adequate protection for most environments.  Files that are opened with applications that include internal controls on code execution are good candidates for this technique.

The Open Confirmation property, enabled through the Confirm open after download setting, provides a notice to the user that allows them to open the file, save the file to disk, or cancel the file open task.  The Always show extension setting adds additional value. This ensures that users can see the file type before attempting to open it.

The Values of confirm after download and always show extension give the users additional information about a file so a decision can be made as to whether it should be opened.

The command line tool, ’assoc’, can be used to determine if a given file type definition exists.  For example, on typical Windows systems the command ’assoc.bat’ returns ’.bat=batfile’ indicating that the extension .bat is defined and that the properties are stored in the Windows Registry under the key batfile.

Windows Explorer can be used to manually display and configure the Actions, Always Show Extension, and Open Confirmation properties.  In Windows 2000 and XP use the File Types tab of the Tools | Folder Options dialog in Windows Explorer.

It must be recognized that performing these changes does not eliminate the danger from malicious code.  Such code could come from a number of sources and use trigger techniques other than the Windows file type open action.  Thus the changes documented here are not a substitute for an anti-virus tool with current definitions.

NOTE:	The application of this change affects the behavior of all Windows applications that utilize the affected Registry settings.'
  desc 'check', 'On Windows NT/2000/2003/XP--
Start the Windows Explorer application. On the Tools menu, select the Folder Options… item. On the Folder Options window, select the File Types tab. For each of the file types in the table below, select the Edit… button for Windows NT or the Advanced button for Windows 2000/2003/XP. On the Edit File Type window:
a) Determine the value of the Confirm open after download option.
b) Determine the value of the Always show extension option.

On Windows 7/8/2008/2008R2--
Start the Windows Explorer application. Click on the drop-down arrow of the Organize option and select Folder and Search Options. In the Folder Options dialog box, click on the View TAB.
a) Ensure the "Hide extensions for known file types" is not selected.

File Type	Extensions		
Adobe Acrobat Document	         PDF		
Microsoft PowerPoint Slide Show	 PPS
LotusScript Library	         LSL		
Microsoft PowerPoint Template	 POT
LotusScript Object	         LSO		
Microsoft Word Backup Document	 WBK
Jscript	                         JS,JSE		
HTML Applications	         HTA
LotusScript Source	         LSS		
Microsoft Word Document	         DOC
Microsoft Excel Backup File      XLK		
Microsoft Word Template	         DOT
Microsoft Excel OLE DB Query Files	RQY		
MS-DOS Batch File	         BAT
Microsoft Excel Web Query File	 IQY		
PostScript	                 PS,EPS
Microsoft Excel Template	 XLT		
Rich Text Format	         RTF
Microsoft Excel Worksheet	 XLS,XLB		
WordPerfect Coach	         WCH
VISIO	                         VSS,VST,VSD,VSW
Microsoft Access	         AD, ADP,MDB,MDE
Shockwave	                 DCR,DXR,DIR,SPL, SWF
Flash	                         FLS
Shell Scrap Object	         SHS, SHB		
WordPerfect Macro	         WCM
Windows Script Component	 WSC, SCT
Windows Script File	         WSF
Windows Script Host Settings File	WSH
VBScript	                 VBE, VBS
Microsoft PowerPoint Presentation	PPT

NOTE: The File Type strings (e.g., “LotusScript Library”) may vary according to the specific software release. The key element for the check is the Extension value.

Criteria:  If a file type is not defined, this is not a Finding.
a) If the Confirm open after download option in Windows NT/2000/2003/XP is not enabled for each file type, then this is a Finding. In Windows 7/8/2008/2008R2, this is Not Applicable.
b) If the Always show extension option in Windows NT/2000/2003/XP is not enabled for each file type, then this is a Finding.
c) If the Hide extensions for know file types in Windows 7/8/2008/2008R2 is selected, then this is a Finding.
 
*Note: this check does not apply to Windows Vista'
  desc 'fix', 'For each of the filetypes in question, verify the Confirm after download option and the always show extension option are checked.'
  impact 0.5
  ref 'DPMS Target Desktop Application - General'
  tag check_id: 'C-3193r5_chk'
  tag severity: 'medium'
  tag gid: 'V-6879'
  tag rid: 'SV-7146r2_rule'
  tag stig_id: 'DTGW005'
  tag gtitle: 'DTGW005-Open_restricted File Type Properties'
  tag fix_id: 'F-6567r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
end
