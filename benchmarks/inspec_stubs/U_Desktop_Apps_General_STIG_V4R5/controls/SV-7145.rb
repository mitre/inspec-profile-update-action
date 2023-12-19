control 'SV-7145' do
  title 'Execution Restricted File Type Properties'
  desc 'For certain file types, it is necessary to take steps to ensure that the default method of opening the file does not allow mobile code to be executed.  Two techniques to achieve this goal are discussed here—altering the default file type Action and deleting the file type definition.  Although methods of removing Microsoft’s Windows Script Host (WSH) component might meet most of this requirement, that technique should not be the first choice.  It would disable functionality that might be in use for other purposes, and the specific method used would have to be compatible with the Windows File Protection (WFP) feature present in later versions of Windows.

The default Action property can be altered to change the standard default Action from Open to Edit.  When this technique is used, instead of executing a program with the file contents as code, an editor is opened with the file contents as a document.  For example for a .vbs file, the Open action may be the command ’C:\\WINNT\\System32\\Wscript.exe "%1" %*’ and the Edit action may be the command ‘C:\\WINNT\\System32\\Notepad.exe "%1" %*’.  Changing the default action to Edit results in a Notepad window opening up instead of the file being executed by the Windows Scripting Host when the .vbs file is opened.  For non-technical user communities, an alternative that may be more appropriate is to have the Edit action be the command ’C:\\WINNT\\System32\\Notepad.exe "C:\\MC_Warn.txt"’, where the file C:\\MC_Warn.txt is created locally and contains a warning that the user has attempted to open a potentially dangerous file.

When altering the default file type Action is the technique used, the Always show extension setting adds additional value.  This ensures that users can see the file type before attempting to open it.

While the alternate technique of deleting existing Windows file type definitions does provide security, it is not always a more secure long-term solution.  During maintenance or product installation, a non-existent file type is usually defined while existing file type properties are usually not overwritten.

Regardless of which technique is used, the significant result is that when an attempt is made to open certain files using default application actions, any code in the file is not executed.

FIle extensions of certain files should not be hidden.  Users can double click a file without knowing what type of file (or which application) is being opened.'
  desc 'check', 'On Windows NT/2000/2003/XP--
Start the Windows Explorer application. 

On the Tools menu, select the Folder Options… item. On the Folder Options window, select the File Types tab. For each of the file types in the table below, select the Edit… button for Windows NT or the Advanced button for Windows 2000/2003/XP. 

On Windows 7/8/2008/2008R2--
Click on Start. Select Default Programs from the right side of the menu. Choose the Associate a file or protocol with a program option.
 
a) Determine the default Action by looking in the Actions: list for an action in bold font. A typical default action is indicated as “Open”. If none of the entries in the Actions: list appears in bold font, the “Open” action is the default Action. Select the default Action and the Edit… button to determine the application used to perform the action.
b) Determine the value of the Always show extension option.

File Type	Extensions	
JScript Script File	JS		
Windows Script Component	SCT,WSC
JScript Encoded Script File	JSE		
Windows Script File	WSF
Scrap object	SHS,SHB		
Windows Script Host Settings File	WSH
HTML Applications as Mobile Code	HTA			
VBScript Encoded Script File	VBE			
VBScript Script File	VBS			

NOTE: The File Type strings (e.g., “JScript Script File”) may vary according to the specific software release. The key element for the check is the Extension value.


Criteria:  If a file type is not defined, this is not a Finding.
a) If the application defined to perform the default Action could execute code in the file, then this is a Finding.  For example, if the default Action for file type .VBS specifies wscript.exe as the application, a Finding is indicated.  On the other hand, if the default Action for any file type specifies notepad.exe as the application, there is not a Finding.
b) If the Always show extension option is not enabled for each file type, then this is a Finding.


For Windows Vista open the Control Panel select Default Programs select Associate a file type or protocol with a Program:

a) Determine the default program by looking in the Current Default: list. A typical default action is indicated as “Open”. If none of the entries in the Actions: list appears in bold font, the “Open” action is the default Action. Select the default Action and the Edit… button to determine the application used to perform the action.
b) Determine the value of the Always show extension option.

File Type	Extensions		File Type	Extensions
JScript Script File	JS		Windows Script Component	SCT,WSC
JScript Encoded Script File	JSE		Windows Script File	WSF
Scrap object	SHS,SHB		Windows Script Host Settings File	WSH
HTML Applications as Mobile Code	HTA			
VBScript Encoded Script File	VBE			
VBScript Script File	VBS			

NOTE: The File Type strings (e.g., “JScript Script File”) may vary according to the specific software release. The key element for the check is the Extension value.

Criteria:  If a file type is not defined, this is not a Finding.
a) If the application defined in the Current Default list could execute code in the file, then this is a Finding.  For example, if the default program for file type .VBS specifies wscript.exe as the application, a Finding is indicated.  On the other hand, if the default Action for any file type specifies notepad.exe as the application, there is not a Finding.'
  desc 'fix', 'Change the default action to an application that will not execute the file such as notepad.exe  and ensure that the Always show extension is enabled for the filetype in question.'
  impact 0.5
  ref 'DPMS Target Desktop Application - General'
  tag check_id: 'C-3192r2_chk'
  tag severity: 'medium'
  tag gid: 'V-6878'
  tag rid: 'SV-7145r2_rule'
  tag stig_id: 'DTGW004'
  tag gtitle: 'DTGW004-Execution Restricted File Type Properties'
  tag fix_id: 'F-6566r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
end
