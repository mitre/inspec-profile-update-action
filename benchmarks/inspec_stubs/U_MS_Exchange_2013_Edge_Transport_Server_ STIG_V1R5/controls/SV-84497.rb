control 'SV-84497' do
  title 'Exchange Attachment filtering must remove undesirable attachments by file type.'
  desc 'By performing filtering at the perimeter, up to 90 percent of spam, malware, and other undesirable messages are eliminated from the message stream rather than admitting them into the mail server environment. 

Attachments are being used more frequently for different forms of attacks. By filtering undesirable attachments a large percent of malicious code can be prevented from entering the system. Attachments must be controlled at the entry point into the email environment to prevent successful attachment-based attacks. The following is a basic list of known attachments that should be filtered from Internet mail attachments:

*.ade  *.crt  *.jse  *.msi  *.scr  *.wsh  *.dir
*.adp  *.csh  *.ksh  *.msp  *.sct  *.htm  *.dcr
*.app  *.exe  *.lnk  *.mst  *.shb  *.html  *.plg
*.asx  *.fxp  *.mda  *.ops  *.shs  *.htc  *.spl
*.bas  *.hlp  *.mdb  *.pcd  *.url  *.mht  *.swf
*.bat  *.hta  *.mde  *.pif  *.vb  *.mhtml  *.zip
*.chm  *.inf  *.mdt  *.prf  *.vbe  *.shtm  
*.cmd  *.ins  *.mdw  *.prg  *.vbs  *.shtml  
*.com  *.isp  *.mdz  *.reg  *.wsc  *.stm  
*.cpl  *.js  *.msc  *.scf  *.wsf  *.xml'
  desc 'check', 'Review the Email Domain Security Plan (EDSP).

Determine the list of undesirable attachment types that should be stripped.

Open the Exchange Management Shell and enter the following command:

Get-AttachmentFilterEntry 

For each attachment type, if the values returned are different from the EDSP documented attachment types, this is a finding.'
  desc 'fix', "Update the EDSP.

Open the Exchange Management Shell and enter the following command:

Add-AttachmentFilterEntry -Name <'*.FileExtension'> -Type FileName

Repeat the procedure for each undesirable attachment type."
  impact 0.5
  ref 'DPMS Target Microsoft Exchange 2013 Edge Transport Server'
  tag check_id: 'C-70343r1_chk'
  tag severity: 'medium'
  tag gid: 'V-69875'
  tag rid: 'SV-84497r2_rule'
  tag stig_id: 'EX13-EG-000200'
  tag gtitle: 'SRG-APP-000261'
  tag fix_id: 'F-76105r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001308']
  tag nist: ['SI-8 (2)']
end
