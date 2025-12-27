control 'SV-44057' do
  title 'Attachment filtering must remove undesirable attachments by file type.'
  desc 'By performing filtering at the perimeter, up to 90 percent of spam, malware, and other undesirable messages are eliminated from the message stream rather than admitting them into the mail server environment. Attachments are being used more frequently for different forms of attacks. By filtering undesirable attachments a large percent of malicious code can be prevented from entering the system. Attachments must be controlled at the entry point into the email environment to prevent successful attachment-based attacks. The following is a basic list of known attachments that should be filtered from Internet mail attachments.

*.ade *.crt *.jse *.msi *.scr *.wsh *.dir *.adp *.csh *.ksh *.msp *.sct *.htm *.dcr *.app *.exe *.lnk *.mst *.shb *.html *.plg *.asx *.fxp *.mda *.ops *.shs *.htc *.spl *.bas *.hlp *.mdb *.pcd *.url *.mht *.swf
*.bat *.hta *.mde *.pif *.vb *.mhtml  *.chm *.inf *.mdt *.prf *.vbe *.shtm  *.cmd *.ins *.mdw *.prg *.vbs *.shtml 
*.com *.isp *.mdz *.reg *.wsc *.stm 
*.cpl *.js *.msc *.scf *.wsf'
  desc 'check', 'Obtain the Email Domain Security Plan (EDSP) and locate the list of undesirable attachment types that should be stripped.

Open the Exchange Management Shell and enter the following command:

Get-AttachmentFilterEntry 

If the values returned are different from the EDSP documented attachment types, this is a finding.'
  desc 'fix', "Open the Exchange Management Shell and enter the following command:

Add-AttachmentFilterEntry -Name <'*.FileExtension'> -Type FileName"
  impact 0.5
  ref 'DPMS Target Microsoft Exchange Server 2010'
  tag check_id: 'C-41746r1_chk'
  tag severity: 'medium'
  tag gid: 'V-33637'
  tag rid: 'SV-44057r2_rule'
  tag stig_id: 'Exch-2-302'
  tag gtitle: 'Exch-2-302'
  tag fix_id: 'F-37529r1_fix'
  tag 'documentable'
end
