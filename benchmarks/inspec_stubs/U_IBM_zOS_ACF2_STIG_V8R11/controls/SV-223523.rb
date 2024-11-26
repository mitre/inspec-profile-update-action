control 'SV-223523' do
  title 'IBM z/OS FTP Control cards must be properly stored in a secure PDS file.'
  desc 'Configuring the operating system to implement organization-wide security implementation guides and security checklists ensures compliance with federal standards and establishes a common security baseline across DoD that reflects the most restrictive security posture consistent with operational requirements.'
  desc 'check', 'Provide a list(s) of the locations for all FTP Control cards within a given application/AIS, ensuring no FTP control cards are within in-stream JCL, JCL libraries or any open access data sets. The list must indicate which application uses the PDS, and access requirements for those PDSes (who and what level of access). Lists/spreadsheet used for documenting the meeting of this requirement must be maintained by the responsible Application/AIS Team, available upon request and not maintained by Mainframe ISSO.

Obtain the list/spreadsheet from the Application/AIS Team.

Access to FTP scripts and/or data files located on host system(s) that contain FTP userid and or password will be restricted to those individuals responsible for the application connectivity and who have a legitimate requirement to know the userid and password on a remote system. 

FTP Control Cards within In-stream JCL, within JCL libraries or open access libraries/data sets is a finding. 

If there is anyone not listed within the spreadsheet by userid that has access of Read or greater to the FTP control cards, this is a finding.'
  desc 'fix', 'Create a list or spreadsheet of the locations where FTP control cards are stored, who should have access to those libraries, and which applications the FTP control cards are for.

Add Columns for all people permitted access to the secured PDS.

Make sure that the FTP control Cards for each FTP are stored in a secure PDS and that they are not placed in the JCL libraries or in the in-stream JCL for each FTP.'
  impact 0.5
  ref 'DPMS Target IBM zOS ACF2'
  tag check_id: 'C-25196r504627_chk'
  tag severity: 'medium'
  tag gid: 'V-223523'
  tag rid: 'SV-223523r533198_rule'
  tag stig_id: 'ACF2-FT-000070'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-25184r504628_fix'
  tag 'documentable'
  tag legacy: ['SV-106855', 'V-97751']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
