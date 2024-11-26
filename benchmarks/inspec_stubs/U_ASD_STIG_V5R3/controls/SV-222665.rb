control 'SV-222665' do
  title 'The designer must ensure uncategorized or emerging mobile code is not used in applications.'
  desc 'By definition, mobile code is software obtained from remote systems outside the enclave boundary, transferred across a network, and then downloaded and executed on a local system without explicit installation or execution by the recipient.  

For a complete list of mobile code categorizations, refer to the overview document included with this STIG.
Categorized mobile code includes but is not limited to:

- ActiveX
- Windows Scripting Host when used as mobile code
- Unix Shell Scripts when used as mobile code
- DOS batch scripts when used as mobile code
- Java applets and other Java mobile code
- Visual Basic for Applications (VBA)
- LotusScript
- PerfectScript
- Postscript
- JavaScript (including Jscript and ECMAScript variants)
- VBScript
- Portable Document Format (PDF)
- Shockwave/Flash
- Rich Internet Applications

The following technologies are not currently designated as mobile code:

- XML
- SMIL
- QuickTime
- VRML (exclusive of any associated Java applets or JavaScript scripts)

The following are outside the scope of the mobile code requirements:

- Scripts and applets embedded in or linked to web pages and executed in the context of the web server.  Examples of this are Java servlets, Java Server pages, CGI, Active Server Pages, CFML, PHP, SSI, server-side JavaScript, server-side LotusScript.
- Local programs and command scripts 
- Distributed object-oriented programming systems (e.g., CORBA, DCOM).
- Software patches, updates, including self-extracting updates - software updates that must be invoked explicitly by the user are outside the mobile code policy.  Examples of technologies in this area include: Netscape SmartUpdate, Microsoft Windows Update, Netscape web browser plug-ins and Linux.

If other types of mobile code technologies are present that are not listed here, a written waiver must be granted by the CIO (allowing use of emerging mobile code technology). Also uncategorized mobile code must be submitted for AO approval.'
  desc 'check', 'Review the application documentation and interview application administrator.

Determine what mobile code types are used by the application.

If uncategorized mobile code types are found, ask the application administrator to provide the documented waiver and risk acceptance. If the application is using uncategorized or emerging mobile code and there is no waiver provided, this is a finding.'
  desc 'fix', 'Remove uncategorized or emerging mobile code from the application or obtain a waiver and risk acceptance to operate.'
  impact 0.5
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-24335r493903_chk'
  tag severity: 'medium'
  tag gid: 'V-222665'
  tag rid: 'SV-222665r879887_rule'
  tag stig_id: 'APSC-DV-003300'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-24324r493904_fix'
  tag 'documentable'
  tag legacy: ['SV-85031', 'V-70409']
  tag cci: ['CCI-001167']
  tag nist: ['SC-18 (2)']
end
